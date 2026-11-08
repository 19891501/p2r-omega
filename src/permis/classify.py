"""Classement heuristique d'un nœud n8n.

Les ensembles d'opérations reprennent le prototype, avec deux corrections :
Send and Wait n'est pas un envoi client, et une adresse fixe ne prouve pas
qu'il s'agit d'un client plutôt que de l'opérateur.
"""

from __future__ import annotations

from permis.secrets import scrub

SEND = {"send", "reply", "sendAndWait", "post", "create", "message", "sendMessage"}
DELETE = {"delete", "remove", "deleteAll", "clear", "archive", "trash"}
WRITE = {
    "markAsUnread",
    "update",
    "append",
    "appendOrUpdate",
    "upsert",
    "addLabels",
    "removeLabels",
    "markAsRead",
    "move",
}
READ = {"get", "getAll", "read", "search", "list", "lookup"}
DEFAULT_OP = {
    "gmail": "send",
    "gmailTool": "send",
    "slack": "post",
    "notion": "create",
    "telegram": "sendMessage",
    "microsoftOutlook": "send",
}
EXTERNAL = {
    "gmail",
    "gmailTool",
    "microsoftOutlook",
    "microsoftOutlookTool",
    "telegram",
    "twilio",
    "whatsApp",
    "emailSend",
    "linkedIn",
    "twitter",
    "facebookGraphApi",
    "stripe",
    "paypal",
}
SKIP_PARTS = (
    "stickyNote",
    "lmChat",
    "outputParser",
    "memory",
    "embeddings",
    "if",
    "filter",
    "switch",
    "merge",
    "set",
    "noOp",
    "splitInBatches",
    "Trigger",
    "trigger",
)
CODE_TYPES = {"code", "function", "functionItem", "executeCommand", "ssh"}
HTTP_TYPES = {"httpRequest", "httpRequestTool", "toolHttpRequest"}
RECIPIENT_KEYS = ("sendTo", "to", "toEmail", "recipient", "recipients", "email", "phone", "chatId")


def short_type(node: dict) -> str:
    raw = node.get("type")
    if not isinstance(raw, str):
        return ""
    return raw.split(".")[-1]


def skipped(node: dict) -> bool:
    name = short_type(node)
    if name in {"agent", "openAi", "chainLlm", "wait"}:
        return True
    if name == "gmailTool":
        return False
    return any(part in name for part in SKIP_PARTS)


def is_agent(node: dict | None) -> bool:
    if not isinstance(node, dict):
        return False
    return short_type(node) in {"agent", "openAi", "chainLlm"}


def _parameters(node: dict) -> dict:
    params = node.get("parameters")
    return params if isinstance(params, dict) else {}


def recipient_mode(value) -> str:
    """expression, litteral, mixte ou absent. Ne dit pas si c'est le client."""
    if value is None or value == "":
        return "absent"
    if isinstance(value, list):
        modes = {recipient_mode(item) for item in value}
        modes.discard("absent")
        if not modes:
            return "absent"
        if len(modes) > 1:
            return "mixte"
        return modes.pop()
    if not isinstance(value, str):
        return "expression"
    text = value.strip()
    if not text:
        return "absent"
    if text.startswith("=") or "{{" in text:
        return "expression"
    return "litteral"


def extract_recipient(params: dict) -> tuple[str | None, object]:
    for key in RECIPIENT_KEYS:
        if key in params and params[key] not in (None, ""):
            return key, params[key]
    return None, None


def _show(value, limit: int = 80) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = str(value)
    text = scrub(text).replace("|", "/").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def classify_node(node: dict) -> dict:
    """Retourne effet, action, preuve, destinataire.

    preuve = PROUVÉ si l'opération est écrite dans le nœud, INCONNU si on
    s'appuie sur un défaut, CONFLIT si deux champs se contredisent.
    Le champ destinataire décrit la forme de l'adresse, pas la relation
    (vous / client), qui reste non prouvée dans tous les cas.
    """
    name = short_type(node)
    params = _parameters(node)
    operation = params.get("operation")
    default = DEFAULT_OP.get(name.replace("Tool", "")) or DEFAULT_OP.get(name)
    op = operation or default
    resource = params.get("resource")
    _, recipient = extract_recipient(params)
    mode = recipient_mode(recipient)

    if operation == "sendAndWait":
        return {
            "effet": "VALIDATION",
            "action": f"{name} : Send and Wait (demande une réponse humaine)",
            "preuve": "PROUVÉ",
            "destinataire": mode,
            "apercu": _show(recipient) if mode == "litteral" else "",
        }

    if resource == "draft":
        if isinstance(operation, str) and operation in SEND - {"sendAndWait"}:
            return _row(
                "ÉCRITURE",
                f"{name} : brouillon, mais l'opération est {operation}",
                "CONFLIT",
                mode,
            )
        proof = "PROUVÉ" if operation else "INCONNU"
        return _row("ÉCRITURE", f"{name} : crée un brouillon (pas d'envoi)", proof, mode)

    if (
        resource
        and resource not in ("message",)
        and not operation
        and name.startswith(("gmail", "microsoftOutlook"))
    ):
        effet = "LECTURE" if params.get("returnAll") is not None else "INCONNU"
        return _row(effet, f"{name} : {resource}, opération par défaut", "INCONNU", mode)

    if "sendTo" in params and ("subject" in params or "message" in params):
        return _send_row(name, mode, recipient, "PROUVÉ")

    if name.startswith("googleSheets") and not operation and "columns" not in params:
        return _row("LECTURE", f"{name} : lecture (opération par défaut)", "INCONNU", "absent")

    if name in {"executeWorkflow", "executeWorkflowTrigger"}:
        return _row(
            "SOUS-WORKFLOW",
            f"{name} : appelle un autre workflow, absent de ce fichier",
            "INCONNU",
            "absent",
        )

    if name in CODE_TYPES:
        return _row("CODE", f"{name} : exécute du code arbitraire", "INCONNU", "absent")

    if name in HTTP_TYPES:
        method = params.get("method") or "GET"
        method_text = method.upper() if isinstance(method, str) else "GET"
        url = params.get("url")
        shown = _show(url) if isinstance(url, str) and url else "(URL non lisible)"
        if method_text == "GET":
            return _row("LECTURE", f"appel web {method_text} vers {shown}", "INCONNU", "absent")
        if method_text == "DELETE":
            return _row("IRRÉVERSIBLE", f"appel web {method_text} vers {shown}", "INCONNU", "absent")
        return _row("ÉCRITURE", f"appel web {method_text} vers {shown}", "INCONNU", "absent")

    if op in DELETE:
        proof = "PROUVÉ" if operation else "INCONNU"
        return _row("IRRÉVERSIBLE", f"{name} : {op}", proof, mode)
    if op in SEND:
        return _send_row(name, mode, recipient, "PROUVÉ" if operation else "INCONNU", op=op)
    if op in WRITE:
        proof = "PROUVÉ" if operation else "INCONNU"
        return _row("ÉCRITURE", f"{name} : {op}", proof, mode)
    if op in READ:
        proof = "PROUVÉ" if operation else "INCONNU"
        return _row("LECTURE", f"{name} : {op}", proof, mode)
    return _row("INCONNU", f"{name} : opération {op or 'non précisée'}", "INCONNU", mode)


def _send_row(name: str, mode: str, recipient, proof: str, op: str | None = None) -> dict:
    kind = "ENVOI EXTERNE" if name in EXTERNAL or name.replace("Tool", "") in EXTERNAL else "ENVOI INTERNE"
    if mode == "expression":
        detail = "destinataire calculé"
    elif mode == "litteral":
        detail = f"envoi à {_show(recipient, 60)}"
    elif mode == "mixte":
        detail = "destinataires mixtes"
    elif op:
        detail = str(op)
    else:
        detail = "destinataire absent du nœud"
    return _row(kind, f"{name} : {detail}", proof, mode, _show(recipient, 60) if mode == "litteral" else "")


def _row(effet: str, action: str, preuve: str, mode: str, apercu: str = "") -> dict:
    return {
        "effet": effet,
        "action": scrub(action),
        "preuve": preuve,
        "destinataire": mode,
        "apercu": apercu,
    }
