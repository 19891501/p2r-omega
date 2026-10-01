"""Reservation-first execution and signed observation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .effect import effect_identity, execution_key
from .errors import ExecutionError, PreDispatchError, RegistryError
from .receipt import build_receipt, verify_receipt
from .verify import verify_object


class ExecutionContext:
    def __init__(
        self,
        *,
        keyring,
        universe_resolver,
        registry=None,
        observer_signer=None,
        observer_scopes: dict[str, list[str]] | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self.keyring = keyring
        self.universe_resolver = universe_resolver
        self.registry = registry
        self.observer_signer = observer_signer
        self.observer_scopes = observer_scopes or {}
        self._clock = clock or (lambda: int(time.time()))

    @property
    def now(self) -> int:
        return int(self._clock())


def _require_registry(ctx):
    if ctx.registry is None:
        raise ExecutionError("REGISTRY_REQUIRED")
    if ctx.observer_signer is None:
        raise ExecutionError("OBSERVER_SIGNER_REQUIRED")


def execute(p2r, ctx, action, action_semantics="idempotent"):
    if action_semantics not in {"idempotent", "at_most_once"}:
        raise ExecutionError("ACTION_SEMANTICS_INVALID")
    verify_object(p2r, ctx)
    _require_registry(ctx)

    eid = effect_identity(p2r)
    ekey = execution_key(p2r)
    policy = p2r.get("execution_policy", {}).get("on_same_effect", "deny")
    timeout = p2r.get("execution_policy", {}).get("reservation_timeout_seconds", 300)
    decision = ctx.registry.reserve(ekey, eid, policy, ctx.now, reservation_timeout=timeout)
    if decision.kind == "RETRY":
        if not decision.receipt_json:
            raise ExecutionError("RETRY_RECEIPT_MISSING")
        import json
        try:
            cached = json.loads(decision.receipt_json)
        except json.JSONDecodeError as exc:
            raise ExecutionError("RETRY_RECEIPT_INVALID", str(exc)) from exc
        verify_receipt(cached, ctx.keyring, ctx.observer_scopes)
        if cached.get("action_semantics") != action_semantics:
            raise ExecutionError("ACTION_SEMANTICS_MISMATCH")
        if cached.get("payload_digest") != p2r["payload_digest"]["value"]:
            raise ExecutionError("RETRY_RECEIPT_PAYLOAD_MISMATCH")
        if cached.get("effect_identity") != eid:
            raise ExecutionError("RETRY_RECEIPT_EFFECT_MISMATCH")
        if cached.get("execution_key") != ekey:
            raise ExecutionError("RETRY_RECEIPT_EXECUTION_KEY_MISMATCH")
        return cached
    if decision.kind == "ALREADY_RESERVED":
        raise ExecutionError("ALREADY_RESERVED")
    if decision.kind == "RECONCILIATION_REQUIRED":
        raise ExecutionError("EFFECT_RECONCILIATION_REQUIRED")
    if decision.kind == "EFFECT_IN_PROGRESS":
        raise ExecutionError("EFFECT_IN_PROGRESS")
    if decision.kind == "EFFECT_ALREADY_EXECUTED":
        raise ExecutionError("EFFECT_ALREADY_EXECUTED")
    if decision.kind != "NEW":
        raise ExecutionError("REGISTRY_UNKNOWN_DECISION")

    started = False
    try:
        started = True
        observed = action(p2r["effect"], ekey)
        receipt = build_receipt(
            payload_digest=p2r["payload_digest"]["value"],
            execution_key=ekey,
            effect_identity=eid,
            action_semantics=action_semantics,
            observed_effect=observed,
            observer_id=ctx.observer_signer.signer_id,
            observer_scope=ctx.observer_scopes.get(ctx.observer_signer.signer_id, []),
            observed_at=ctx.now,
            signer=ctx.observer_signer,
        )
        verify_receipt(receipt, ctx.keyring, ctx.observer_scopes)
        ctx.registry.mark_executed(ekey, receipt, ctx.now)
        return receipt
    except PreDispatchError:
        # The adapter explicitly guarantees that no external dispatch occurred.
        ctx.registry.abandon_before_dispatch(ekey)
        raise
    except Exception:
        # Once the action may have been invoked, failure is ambiguous by default.
        if started:
            try:
                ctx.registry.mark_ambiguous(ekey, ctx.now)
            except RegistryError:
                pass
        raise
