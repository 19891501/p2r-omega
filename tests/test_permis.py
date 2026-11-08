"""Permis d'agir : classement, secrets, correction Send and Wait, reçu p2r."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from p2r.digest import sha256_b64
from p2r.keys import LocalSigner
from permis.analyze import analyze_path, analyze_workflow
from permis.sign import sign_envelope, verify_envelope, write_private_key
from permis.workflow import dump_bytes, load_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "permis" / "relance.json"
SRC = ROOT / "src"
SECRET = "sk-testSecretValueShouldNeverAppear99"
PASSWORD = "s3cret-password"
WEBHOOK = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"

pytestmark = pytest.mark.filterwarnings("ignore")


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "permis", *args],
        cwd=cwd or ROOT,
        env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": str(SRC)},
        text=True,
        capture_output=True,
        check=False,
    )


def _node(name, type_, parameters=None, position=None, credentials=None):
    node = {
        "name": name,
        "type": type_,
        "typeVersion": 1,
        "position": position or [0, 0],
        "parameters": parameters or {},
    }
    if credentials:
        node["credentials"] = credentials
    return node


def _link(source, targets, kind="main"):
    return {source: {kind: [[{"node": target, "type": kind, "index": 0} for target in targets]]}}


def _merge(*parts):
    connections = {}
    for part in parts:
        connections.update(part)
    return connections


def _workflow(name, nodes, connections, **extra):
    workflow = {"name": name, "nodes": nodes, "connections": connections}
    workflow.update(extra)
    return workflow


def _analyze(workflow, **kwargs):
    raw = dump_bytes(workflow)
    return analyze_workflow(load_bytes(raw), filename="flux.json", file_sha256=sha256_b64(raw), **kwargs)


def _by_name(permis):
    return {row["noeud"]: row for row in permis["rows"]}


def test_relance_reference_shape():
    analysis = analyze_path(FIXTURE)
    rows = _by_name(analysis.permis)
    assert rows["Envoyer au client"]["verdict"] == "BLOQUER"
    assert rows["Envoyer au client"]["effet"] == "ENVOI EXTERNE"
    assert "probable tiers" in rows["Envoyer au client"]["note"]
    assert rows["Envoyer au client"]["qui_decide"] == "règle fixe, contenu produit par une IA"
    assert rows["Envoyer au client"]["validation_humaine"] == "non"
    assert rows["Envoyer au client"]["preuve"] == "PROUVÉ"
    legal = rows["Alerter le juridique"]
    assert legal["verdict"] == "INCONNU"
    assert "vous-même" in legal["note"]
    assert "user@example.com" in legal["action"]
    assert rows["Mettre en forme"]["verdict"] == "INCONNU"
    assert rows["Mettre en forme"]["effet"] == "CODE"
    assert rows["Mettre à jour la facture"]["verdict"] == "À SURVEILLER"
    assert rows["Journal"]["verdict"] == "À SURVEILLER"
    assert rows["Slack erreur"]["effet"] == "ENVOI INTERNE"
    assert rows["Slack vide"]["preuve"] == "INCONNU"
    assert rows["Lire factures"]["verdict"] == "AUTORISÉ"
    assert rows["Lire factures"]["qui_decide"] == "règle fixe"
    assert "Modèle" not in rows
    assert "Agent relance" not in rows
    assert analysis.permis["summary"] == {
        "BLOQUER": 1,
        "INCONNU": 2,
        "À SURVEILLER": 4,
        "AUTORISÉ": 1,
    }
    assert analysis.permis["workflow"]["agents"] == ["Agent relance"]
    joined = " ".join(analysis.permis["limits"])
    assert "heuristique" in joined
    assert "AI Act" in joined
    assert "contourn" in joined
    assert "INCONNU" in joined
    assert "secret" in joined.lower()


def test_correction_gates_main_flow_and_is_stable():
    first = analyze_path(FIXTURE)
    second = analyze_path(FIXTURE)
    assert first.permis == second.permis
    assert first.corrected_bytes == second.corrected_bytes
    corrected = json.loads(first.corrected_bytes)
    approvals = [
        node
        for node in corrected["nodes"]
        if isinstance(node.get("parameters"), dict) and node["parameters"].get("operation") == "sendAndWait"
    ]
    assert len(approvals) == 2
    assert approvals[0]["parameters"]["responseType"] == "approval"
    assert approvals[0]["parameters"]["sendTo"] == "approbateur@exemple.invalid"
    assert approvals[0]["credentials"]["gmailOAuth2"]["id"] == "cred-1"
    filters = [node for node in corrected["nodes"] if node["name"].startswith("Permis — filtre")]
    assert filters
    assert "data.approved" in json.dumps(filters[0]["parameters"])
    # Le refus ne revient pas sur l'effet : seule la sortie 0 du filtre y mène.
    for filt in filters:
        true_branch = filt and corrected["connections"][filt["name"]]["main"][0][0]["node"]
        false_branch = corrected["connections"][filt["name"]]["main"][1][0]["node"]
        assert true_branch in {"Envoyer au client", "Alerter le juridique"}
        assert false_branch.startswith("Permis — refus")
    reread = _analyze(corrected, correct=False)
    reread_rows = _by_name(reread.permis)
    assert reread_rows["Envoyer au client"]["verdict"] == "À SURVEILLER"
    assert reread_rows["Envoyer au client"]["validation_humaine"] == "oui"
    assert reread_rows["Alerter le juridique"]["validation_humaine"] == "oui"
    assert first.permis["correction"]["still_blocking"] == []
    assert first.permis["correction"]["secrets_restants"] == 0
    again = _analyze(corrected, correct=True)
    send_and_wait = [
        node
        for node in again.corrected["nodes"]
        if isinstance(node.get("parameters"), dict) and node["parameters"].get("operation") == "sendAndWait"
    ]
    assert len(send_and_wait) == 2


def test_send_and_wait_without_filter_does_not_count_as_a_gate():
    workflow = _workflow(
        "attente",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node(
                "Attente",
                "n8n-nodes-base.gmail",
                {"operation": "sendAndWait", "sendTo": "ops@example.com", "subject": "ok", "message": "ok", "responseType": "approval"},
            ),
            _node(
                "Envoi",
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
            ),
        ],
        _merge(_link("Agent", ["Attente"]), _link("Attente", ["Envoi"])),
    )
    rows = _by_name(_analyze(workflow, correct=False).permis)
    assert rows["Envoi"]["verdict"] == "BLOQUER"
    assert "refus peut continuer" in rows["Envoi"]["note"]
    assert rows["Attente"]["effet"] == "VALIDATION"


def test_approval_filter_on_true_branch_only():
    def gated(false_goes_to_effect: bool):
        workflow = _workflow(
            "filtre",
            [
                _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
                _node(
                    "Attente",
                    "n8n-nodes-base.gmail",
                    {"operation": "sendAndWait", "sendTo": "ops@example.com", "subject": "s", "message": "m"},
                ),
                _node(
                    "Filtre",
                    "n8n-nodes-base.if",
                    {"conditions": {"conditions": [{"leftValue": "={{ $json.data.approved }}"}]}},
                ),
                _node(
                    "Envoi",
                    "n8n-nodes-base.gmail",
                    {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
                ),
                _node("Stop", "n8n-nodes-base.noOp"),
            ],
            {
                "Agent": {"main": [[{"node": "Attente", "type": "main", "index": 0}]]},
                "Attente": {"main": [[{"node": "Filtre", "type": "main", "index": 0}]]},
                "Filtre": {
                    "main": [
                        [{"node": "Stop" if false_goes_to_effect else "Envoi", "type": "main", "index": 0}],
                        [{"node": "Envoi" if false_goes_to_effect else "Stop", "type": "main", "index": 0}],
                    ]
                },
            },
        )
        return _by_name(_analyze(workflow, correct=False).permis)["Envoi"]

    assert gated(False)["validation_humaine"] == "oui"
    assert gated(False)["verdict"] == "À SURVEILLER"
    assert gated(True)["verdict"] == "BLOQUER"


def test_parallel_path_around_a_gate_is_a_bypass_until_patched():
    workflow = _workflow(
        "deux chemins",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node(
                "Attente",
                "n8n-nodes-base.gmail",
                {"operation": "sendAndWait", "sendTo": "ops@example.com", "subject": "s", "message": "m"},
            ),
            _node(
                "Filtre",
                "n8n-nodes-base.if",
                {"conditions": {"conditions": [{"leftValue": "={{ $json.data.approved }}"}]}},
            ),
            _node(
                "Envoi",
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
            ),
        ],
        {
            "Agent": {
                "main": [[
                    {"node": "Attente", "type": "main", "index": 0},
                    {"node": "Envoi", "type": "main", "index": 0},
                ]]
            },
            "Attente": {"main": [[{"node": "Filtre", "type": "main", "index": 0}]]},
            "Filtre": {"main": [[{"node": "Envoi", "type": "main", "index": 0}], []]},
        },
    )
    original = _analyze(workflow, correct=False)
    assert _by_name(original.permis)["Envoi"]["verdict"] == "BLOQUER"
    patched = _analyze(workflow, correct=True)
    reread = _analyze(patched.corrected, correct=False)
    assert _by_name(reread.permis)["Envoi"]["validation_humaine"] == "oui"


def test_wait_between_approval_and_filter_keeps_the_gate():
    workflow = _workflow(
        "set",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node("Attente", "n8n-nodes-base.wait", {"resume": "form"}),
            _node("Préparer", "n8n-nodes-base.set", {}),
            _node(
                "Filtre",
                "n8n-nodes-base.if",
                {"conditions": {"conditions": [{"leftValue": "={{ $json.data.approved }}"}]}},
            ),
            _node(
                "Envoi",
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
            ),
        ],
        _merge(
            _link("Agent", ["Attente"]),
            _link("Attente", ["Préparer"]),
            _link("Préparer", ["Filtre"]),
            _link("Filtre", ["Envoi"]),
        ),
    )
    row = _by_name(_analyze(workflow, correct=False).permis)["Envoi"]
    assert row["validation_humaine"] == "oui"


def test_time_wait_is_not_a_human_gate():
    workflow = _workflow(
        "délai",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node("Délai", "n8n-nodes-base.wait", {"resume": "timeInterval"}),
            _node(
                "Envoi",
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
            ),
        ],
        _merge(_link("Agent", ["Délai"]), _link("Délai", ["Envoi"])),
    )
    assert _by_name(_analyze(workflow, correct=False).permis)["Envoi"]["verdict"] == "BLOQUER"


def test_ai_tool_is_not_covered_by_a_main_flow_gate():
    tool = _node(
        "Outil mail",
        "n8n-nodes-base.gmailTool",
        {"operation": "send", "sendTo": "={{ $fromAI('to') }}", "subject": "s", "message": "m"},
    )
    workflow = _workflow(
        "outil",
        [_node("Agent", "@n8n/n8n-nodes-langchain.agent"), tool],
        {"Outil mail": {"ai_tool": [[{"node": "Agent", "type": "ai_tool", "index": 0}]]}},
    )
    analysis = _analyze(workflow, correct=True)
    row = _by_name(analysis.permis)["Outil mail"]
    assert row["verdict"] == "BLOQUER"
    assert row["qui_decide"].startswith("IA « Agent »")
    assert analysis.permis["correction"]["not_applied"][0]["node"] == "Outil mail"
    assert analysis.permis["correction"]["bypasses"]
    assert analysis.permis["correction"]["still_blocking"] == ["Outil mail"]
    reversed_links = {"Agent": {"ai_tool": [[{"node": "Outil mail", "type": "ai_tool", "index": 0}]]}}
    reversed_row = _by_name(_analyze(_workflow("outil", workflow["nodes"], reversed_links), correct=False).permis)
    assert reversed_row["Outil mail"]["verdict"] == "BLOQUER"


def test_tool_with_fixed_address_is_unknown_not_a_client_send():
    workflow = _workflow(
        "outil fixe",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node(
                "Outil mail",
                "n8n-nodes-base.gmailTool",
                {"operation": "send", "sendTo": "user@example.com", "subject": "s", "message": "m"},
            ),
        ],
        {"Outil mail": {"ai_tool": [[{"node": "Agent", "type": "ai_tool", "index": 0}]]}},
    )
    row = _by_name(_analyze(workflow, correct=False).permis)["Outil mail"]
    assert row["verdict"] == "INCONNU"
    assert "vous-même" in row["note"]


def test_secrets_are_never_printed_and_are_removed_from_the_draft():
    workflow = _workflow(
        "secrets",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node(
                "Appel",
                "n8n-nodes-base.httpRequest",
                {
                    "method": "POST",
                    "url": WEBHOOK,
                    "apiKey": PASSWORD,
                    "headerParameters": {"parameters": [{"name": "Authorization", "value": f"Bearer {SECRET}"}]},
                },
            ),
            _node(
                SECRET,
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": f"={{{{ '{SECRET}' }}}}", "subject": "s", "message": "m"},
            ),
        ],
        _merge(_link("Agent", ["Appel", SECRET])),
    )
    analysis = _analyze(workflow, correct=True)
    blob = json.dumps(analysis.permis, ensure_ascii=False)
    assert SECRET not in blob
    assert PASSWORD not in blob
    assert WEBHOOK not in blob
    assert SECRET not in analysis.corrected_bytes.decode()
    assert PASSWORD not in analysis.corrected_bytes.decode()
    assert "XXXXSECRETXXXX" not in analysis.corrected_bytes.decode()
    assert analysis.permis["secrets"]
    assert all("value" not in item for item in analysis.permis["secrets"])
    assert any(item["kind"] == "nom de nœud" for item in analysis.permis["secrets"])
    rendered = __import__("permis.report", fromlist=["render_markdown"]).render_markdown(
        analysis.permis, signed=False
    )
    assert SECRET not in rendered
    assert PASSWORD not in rendered
    names = [node["name"] for node in analysis.corrected["nodes"]]
    assert SECRET not in names
    assert any(name.startswith("nœud masqué") for name in names)


def test_irreversible_delete_and_draft_conflict_and_subflow():
    workflow = _workflow(
        "autres",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node("Effacer", "n8n-nodes-base.gmail", {"operation": "delete", "resource": "message"}),
            _node("Brouillon", "n8n-nodes-base.gmail", {"resource": "draft", "operation": "send"}),
            _node("Suite", "n8n-nodes-base.executeWorkflow", {"workflowId": "autre"}),
        ],
        _merge(_link("Agent", ["Effacer", "Brouillon", "Suite"])),
    )
    rows = _by_name(_analyze(workflow, correct=False).permis)
    assert rows["Effacer"]["verdict"] == "BLOQUER"
    assert rows["Effacer"]["effet"] == "IRRÉVERSIBLE"
    assert rows["Brouillon"]["preuve"] == "CONFLIT"
    assert rows["Suite"]["verdict"] == "INCONNU"
    assert rows["Suite"]["effet"] == "SOUS-WORKFLOW"


def test_float_position_still_signs(tmp_path):
    workflow = _workflow(
        "virgule",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent", position=[10.5, 20]),
            _node(
                "Envoi",
                "n8n-nodes-base.gmail",
                {"operation": "send", "sendTo": "={{ $json.email }}", "subject": "s", "message": "m"},
                position=[30.25, 40],
            ),
        ],
        _link("Agent", ["Envoi"]),
    )
    path = tmp_path / "virgule.json"
    path.write_bytes(dump_bytes(workflow))
    analysis = analyze_path(path)
    signer = LocalSigner.from_seed("analyste", b"a" * 32)
    envelope = sign_envelope(analysis.permis, signer, observed_at=1_700_000_000)
    result = verify_envelope(envelope, ("analyste", signer.public_key_b64()))
    assert result.ok
    assert result.identity_pinned
    again = sign_envelope(analysis.permis, signer, observed_at=1_700_000_000)
    assert again == envelope


def test_tampered_document_and_unpinned_identity():
    workflow = _workflow(
        "signe",
        [
            _node("Agent", "@n8n/n8n-nodes-langchain.agent"),
            _node("Lire", "n8n-nodes-base.googleSheets", {}),
        ],
        _link("Agent", ["Lire"]),
    )
    analysis = _analyze(workflow, correct=False)
    signer = LocalSigner.from_seed("analyste", b"b" * 32)
    other = LocalSigner.from_seed("autre", b"c" * 32)
    envelope = sign_envelope(analysis.permis, signer, observed_at=10)
    assert verify_envelope(envelope).ok
    assert verify_envelope(envelope).identity_pinned is False
    assert verify_envelope(envelope, ("analyste", signer.public_key_b64())).identity_pinned
    assert not verify_envelope(envelope, ("analyste", other.public_key_b64())).ok
    envelope["permis"]["rows"][0]["verdict"] = "BLOQUER"
    failed = verify_envelope(envelope)
    assert not failed.ok
    assert failed.reason == "PREUVE_DIGEST"
    unsigned = {"permis": analysis.permis, "preuve": None}
    assert verify_envelope(unsigned).reason == "NON_SIGNE"


def test_wrapped_export_and_missing_nodes():
    inner = _workflow("dedans", [_node("Lire", "n8n-nodes-base.googleSheets", {})], {})
    wrapped = load_bytes(json.dumps({"workflow": inner}).encode())
    assert wrapped["name"] == "dedans"
    with pytest.raises(Exception) as exc:
        load_bytes(b"[]")
    assert exc.value.code == "PLUSIEURS_WORKFLOWS"
    with pytest.raises(Exception) as exc:
        load_bytes(b"{}")
    assert exc.value.code == "FICHIER_SANS_NOEUDS"


def test_cli_writes_three_files_and_verifier_roundtrip(tmp_path):
    source = tmp_path / "relance.json"
    source.write_bytes(FIXTURE.read_bytes())
    before = source.read_bytes()
    out = tmp_path / "permis.md"
    key = tmp_path / "clef.json"
    created = _run(["clef", "-o", str(key), "--signer-id", "lhassan"])
    assert created.returncode == 0, created.stderr
    assert SECRET not in created.stdout
    seed = json.loads(key.read_text())["seed_b64"]
    assert seed not in created.stdout
    assert key.stat().st_mode & 0o777 == 0o600
    public = created.stdout.split("public_key: ", 1)[1].strip()
    pin = tmp_path / "publique.json"
    pin.write_text(json.dumps({"signer_id": "lhassan", "public_key": public}) + "\n", encoding="utf-8")
    result = _run(
        ["analyse", str(source), "-o", str(out), "--signer", str(key), "--horodatage", "1700000000"]
    )
    assert result.returncode == 0, result.stderr
    assert source.read_bytes() == before
    assert out.is_file()
    document = tmp_path / "permis.json"
    draft = tmp_path / "permis.workflow.json"
    assert document.is_file() and draft.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Permis d'agir" in text
    assert "heuristique" in text
    assert "BLOQUER" in text
    envelope = json.loads(document.read_text(encoding="utf-8"))
    assert envelope["preuve"]["permis_digest"] in text
    assert seed not in document.read_text(encoding="utf-8")
    checked = _run(["verifier", str(document), "--clef", str(pin), "--workflow", str(source)])
    assert checked.returncode == 0, checked.stderr + checked.stdout
    assert "Identité : épinglée" in checked.stdout
    assert "graine" not in checked.stdout
    english = _run(["verify", str(document)])
    assert english.returncode == 0, english.stdout
    assert "non épinglée" in english.stdout
    tampered = json.loads(document.read_text(encoding="utf-8"))
    tampered["permis"]["summary"]["BLOQUER"] = 9
    bad = tmp_path / "mauvais.json"
    bad.write_text(json.dumps(tampered), encoding="utf-8")
    refused = _run(["verifier", str(bad), "--clef", str(pin)])
    assert refused.returncode == 1
    assert "PREUVE_DIGEST" in refused.stdout
    missing = _run(["analyse", str(tmp_path / "absent.json"), "-o", str(out)])
    assert missing.returncode == 1
    broken = tmp_path / "casse.json"
    broken.write_text("{", encoding="utf-8")
    assert _run(["analyse", str(broken), "-o", str(tmp_path / "x.md")]).returncode == 1


def test_limits_mention_the_honest_gaps():
    analysis = analyze_path(FIXTURE, correct=False)
    text = "\n".join(analysis.permis["limits"])
    assert "ne ferme pas tous les chemins" in text
    assert "adresse fixe" in text
    assert "COMPLETED" in text
    assert "GET" in text
    assert analysis.permis["correction"] is None


def test_error_workflow_and_pindata_are_named_as_unseen():
    workflow = _workflow(
        "bord",
        [_node("Lire", "n8n-nodes-base.googleSheets", {})],
        {},
        settings={"errorWorkflow": "wf-2"},
        pinData={"Lire": [{"json": {"email": "a@b.c"}}]},
    )
    limits = " ".join(_analyze(workflow, correct=False).permis["limits"])
    assert "workflow d'erreur" in limits
    assert "pinData" in limits
    assert "a@b.c" not in json.dumps(_analyze(workflow, correct=False).permis)


def test_help_is_french():
    result = _run(["analyse", "--help"])
    assert result.returncode == 0
    assert "permis" in result.stdout
