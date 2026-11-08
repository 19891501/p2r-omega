"""Ligne de commande. `analyse` et `verifier`, alias anglais `analyze` et `verify`."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from permis.analyze import analyze_path
from permis.errors import PermisError
from permis.report import render_markdown
from permis.sign import load_pin, load_signer, sign_envelope, unsigned_envelope, verify_envelope, write_private_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="permis",
        description="Permis d'agir — ce qu'un workflow n8n peut faire sans demander.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyse = sub.add_parser("analyse", aliases=["analyze"], help="lire un export n8n et écrire le permis")
    analyse.add_argument("workflow", help="export JSON n8n")
    analyse.add_argument("-o", "--output", required=True, help="fichier Markdown, par exemple permis.md")
    analyse.add_argument("--json", dest="json_path", help="fichier JSON (défaut : même nom que -o, en .json)")
    analyse.add_argument("--workflow-corrige", dest="corrected_path", help="brouillon n8n (défaut : <nom>.workflow.json)")
    analyse.add_argument("--sans-correction", action="store_true", help="ne pas écrire le workflow corrigé")
    analyse.add_argument("--signer", help="fichier de clef privée (signer_id + seed_b64)")
    analyse.add_argument("--horodatage", type=int, help="secondes entières pour le reçu (tests et relecture)")

    verifier = sub.add_parser("verifier", aliases=["verify"], help="vérifier le JSON signé")
    verifier.add_argument("document", help="JSON produit par permis analyse")
    verifier.add_argument("--clef", help="clef publique épinglée, ou fichier privé (seule la partie publique est utilisée)")
    verifier.add_argument("--workflow", help="export d'origine : vérifie que l'empreinte correspond")

    clef = sub.add_parser("clef", help="créer une clef de signature")
    clef.add_argument("-o", "--output", required=True, help="fichier privé à créer")
    clef.add_argument("--signer-id", default="permis-d-agir", help="nom du signataire écrit dans le reçu")

    args = parser.parse_args(argv)
    try:
        if args.command in {"analyse", "analyze"}:
            return _analyse(args)
        if args.command in {"verifier", "verify"}:
            return _verifier(args)
        if args.command == "clef":
            return _clef(args)
    except PermisError as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 1
    print("erreur : COMMANDE_INCONNUE", file=sys.stderr)
    return 2


def _analyse(args) -> int:
    source = Path(args.workflow)
    if not source.is_file():
        raise PermisError("FICHIER_ILLISIBLE", "Export introuvable.")
    markdown_path = Path(args.output)
    if markdown_path.exists() and markdown_path.is_dir():
        raise PermisError("SORTIE_INVALIDE", "-o doit être un fichier.")
    analysis = analyze_path(source, correct=not args.sans_correction)
    observed_at = args.horodatage if args.horodatage is not None else int(time.time())
    if args.signer:
        envelope = sign_envelope(analysis.permis, load_signer(Path(args.signer)), observed_at)
        signed = True
        signer_id = envelope["preuve"]["signer_id"]
    else:
        envelope = unsigned_envelope(analysis.permis)
        signed = False
        signer_id = None
    json_path = Path(args.json_path) if args.json_path else markdown_path.with_suffix(".json")
    corrected_path = None
    if not args.sans_correction:
        corrected_path = (
            Path(args.corrected_path) if args.corrected_path else markdown_path.with_suffix(".workflow.json")
        )
        if analysis.corrected_bytes is None:
            raise PermisError("CORRECTION_ABSENTE", "Le brouillon n'a pas été produit.")
        corrected_path.write_bytes(analysis.corrected_bytes)
    markdown = render_markdown(analysis.permis, signed=signed, signer_id=signer_id)
    markdown_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = analysis.permis["summary"]
    print(f"Permis écrit : {markdown_path}")
    print(f"JSON : {json_path}")
    if corrected_path:
        print(f"Workflow corrigé : {corrected_path}")
    print(
        "Résumé : "
        f"{summary['BLOQUER']} à bloquer, "
        f"{summary['INCONNU']} inconnu, "
        f"{summary['À SURVEILLER']} à surveiller, "
        f"{summary['AUTORISÉ']} autorisé."
    )
    if analysis.permis["secrets"]:
        print(
            f"Secrets reconnus : {len(analysis.permis['secrets'])} (valeurs non affichées).",
            file=sys.stderr,
        )
    return 0


def _verifier(args) -> int:
    path = Path(args.document)
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PermisError("JSON_INVALIDE", "Document illisible.") from exc
    pinned = None
    private = False
    if args.clef:
        pinned, private = load_pin(Path(args.clef))
    result = verify_envelope(envelope, pinned)
    if not result.ok:
        if result.workflow_name:
            print(f"Workflow : {result.workflow_name}")
        print(f"Échec : {result.reason}")
        return 1
    if args.workflow:
        _check_source(envelope, Path(args.workflow))
    if result.workflow_name:
        print(f"Workflow : {result.workflow_name}")
    print("Intégrité : oui")
    print(f"Signataire : {result.signer_id}")
    print(f"Empreinte : {result.digest}")
    if result.identity_pinned:
        print("Identité : épinglée (la clef publique transmise à part correspond).")
    else:
        print(
            "Identité : non épinglée. La clef est celle du fichier. "
            "Cela prouve qu'il n'a pas été modifié après signature, pas qui a signé."
        )
    if private:
        print("Attention : le fichier de clef contient la graine privée. Seule la clef publique a été utilisée.")
    if result.summary:
        print(
            "Résumé signé : "
            f"{result.summary.get('BLOQUER', 0)} à bloquer, "
            f"{result.summary.get('INCONNU', 0)} inconnu, "
            f"{result.summary.get('À SURVEILLER', 0)} à surveiller, "
            f"{result.summary.get('AUTORISÉ', 0)} autorisé."
        )
    print("Ce reçu ne prouve pas que le classement est vrai.")
    if args.workflow:
        print("Export d'origine : empreinte identique.")
    return 0


def _check_source(envelope: dict, workflow: Path) -> None:
    from p2r.digest import sha256_b64

    digest = sha256_b64(workflow.read_bytes())
    expected = envelope.get("permis", {}).get("workflow", {}).get("sha256")
    if digest != expected:
        raise PermisError(
            "FICHIER_DIFFERENT",
            "L'empreinte de cet export ne correspond pas au permis.",
        )


def _clef(args) -> int:
    path = Path(args.output)
    if path.exists():
        raise PermisError("CLEF_EXISTE", "Le fichier existe déjà. Choisissez un autre nom.")
    signer = write_private_key(path, args.signer_id)
    print(f"Clef privée écrite : {path}")
    print("Ne versionnez pas ce fichier et ne l'envoyez pas.")
    print("Clef publique (transmissible) :")
    print(f"signer_id: {signer.signer_id}")
    print(f"public_key: {signer.public_key_b64()}")
    return 0


# Réexport utilisé par les tests qui veulent le même encodage que le reçu.