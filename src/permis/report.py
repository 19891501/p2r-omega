"""Mise en page du Permis, une page Markdown."""

from __future__ import annotations

from permis.sign import permis_digest

_VERDICT_ORDER = ("BLOQUER", "INCONNU", "À SURVEILLER", "AUTORISÉ")

_STATIC_LIMITS = (
    "Analyse statique du fichier seulement. Elle ne voit ni les comptes réellement connectés, ni leurs droits (périmètre OAuth), ni les exécutions passées.",
    "Le classement est une heuristique. Il peut se tromper. Ce n'est ni un audit de sécurité, ni un avis juridique, ni une certification AI Act.",
    "Un export n8n peut contenir des secrets en clair. Ceux qui sont reconnus sont signalés sans leur valeur, et retirés du workflow corrigé. Un format non reconnu peut échapper : relisez le fichier avant de le transmettre.",
    "Ajouter Send and Wait ne ferme pas tous les chemins. Un outil d'agent, une autre branche, un sous-workflow, une exécution manuelle du nœud, ou un refus qui reprend le même fil peuvent contourner l'étape.",
    "Le filtre ajouté suppose que la sortie 0 du nœud IF est la branche vraie, et que Send and Wait renvoie data.approved. C'est le comportement actuel de n8n, pas une garantie sur une version future.",
    "Une adresse fixe ne permet pas de distinguer un envoi à vous-même d'un envoi à un client : ce cas est INCONNU. Une adresse calculée reste une cible non prouvée.",
    "Slack est classé envoi interne : un canal partagé avec un client ne se voit pas dans le fichier.",
    "Un HTTP GET est classé lecture : certains GET modifient l'état du serveur. Un POST est classé écriture, même s'il déclenche un envoi.",
    "Le reçu, s'il est présent, signe ce document. Il ne prouve pas que le classement est juste. Le mot COMPLETED du reçu p2r signifie que l'observation a été enregistrée, pas que le workflow a réussi, ni qu'un effet extérieur a eu lieu.",
    "Le workflow corrigé est un brouillon à importer et à tester. L'adresse approbateur@exemple.invalid doit être remplacée. Aucun secret n'est recopié ; une référence Gmail déjà présente n'est reprise que par son id et son nom.",
)


def static_limits() -> list[str]:
    return list(_STATIC_LIMITS)


def render_markdown(permis: dict, *, signed: bool, signer_id: str | None = None) -> str:
    workflow = permis["workflow"]
    summary = permis["summary"]
    digest = permis_digest(permis)
    title = workflow["name"]
    lines = [
        f"# Permis d'agir — « {title} »",
        "",
        (
            f"Fichier analysé : `{workflow['filename']}` · {workflow['nodes']} nœuds · "
            f"{_agents(len(workflow['agents']))}"
        ),
        "",
        f"Empreinte du fichier : `{workflow['sha256']}`",
        "",
        f"**Résumé : {_summary(summary)}.**",
        "",
        "BLOQUER signifie : cet effet peut partir sans validation humaine. "
        "À SURVEILLER : l'effet existe encore (une personne peut l'avoir autorisé, ou ce n'est pas un envoi). "
        "INCONNU : le fichier ne permet pas de trancher. AUTORISÉ : lecture, au sens de cette heuristique.",
        "",
        "| Verdict | Effet | Nœud | Action | Qui décide | Validation humaine avant ? | Statut preuve |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in permis["rows"]:
        cells = [
            row["verdict"],
            row["effet"],
            row["noeud"],
            row["action"],
            row["qui_decide"],
            row["validation_humaine"],
            row["preuve"],
        ]
        lines.append("| " + " | ".join(_cell(item) for item in cells) + " |")
    notes = [row for row in permis["rows"] if row.get("note")]
    lines.extend(["", "## Notes", ""])
    if notes:
        for row in notes:
            lines.append(f"- **{_cell(row['noeud'])}** — {row['note']}")
    else:
        lines.append("Aucune note particulière.")
    lines.extend(["", "## Secrets", ""])
    secrets = permis["secrets"]
    if not secrets:
        lines.append("Aucun secret en clair reconnu dans ce fichier. Cela ne prouve pas qu'il n'y en a pas.")
    else:
        lines.append(
            f"{len(secrets)} valeur(s) reconnue(s) comme secrète(s). La valeur n'est pas recopiée."
        )
        for item in secrets:
            where = item["node"] or "racine du fichier"
            lines.append(
                f"- « {_cell(where)} », chemin `{item['path']}` ({item['kind']}, {item['length']} caractères) : valeur masquée."
            )
    lines.extend(["", "## Workflow corrigé", ""])
    correction = permis["correction"]
    if correction is None:
        lines.append("Pas de fichier corrigé demandé.")
    else:
        lines.append(
            "Un brouillon est produit à côté de ce permis. "
            f"Empreinte du brouillon : `{correction['corrected_sha256']}`."
        )
        if correction["inserted"]:
            lines.append("")
            lines.append("Send and Wait, puis un filtre qui ne laisse passer que l'approbation :")
            for item in correction["inserted"]:
                lines.append(f"- avant « {_cell(item['before'])} »")
        if correction["already_gated"]:
            lines.append("")
            lines.append("Flux principal déjà filtré par une approbation, rien ajouté :")
            for name in correction["already_gated"]:
                lines.append(f"- « {_cell(name)} »")
        if correction["not_applied"]:
            lines.append("")
            lines.append("Pas d'étape ajoutée :")
            for item in correction["not_applied"]:
                lines.append(f"- « {_cell(item['node'])} » — {item['reason']}")
        if correction["bypasses"]:
            lines.append("")
            lines.append("Contournement qui reste ouvert :")
            for item in correction["bypasses"]:
                lines.append(f"- « {_cell(item['node'])} » — {item['reason']}")
        reread = correction["reread"]
        lines.append("")
        lines.append(f"Relecture du brouillon : {_summary(reread)}.")
        if correction["still_blocking"]:
            lines.append(
                "Encore BLOQUER après correction : "
                + ", ".join(f"« {_cell(name)} »" for name in correction["still_blocking"])
                + "."
            )
        if correction["secrets_restants"]:
            lines.append(
                f"Le brouillon contient encore {correction['secrets_restants']} secret(s) reconnu(s) : ne le transmettez pas en l'état."
            )
        lines.append("")
        lines.append(
            "L'adresse d'approbation est `approbateur@exemple.invalid`. "
            "Remplacez-la, choisissez le compte Gmail à l'import, et testez le refus : l'effet ne doit pas partir."
        )
    lines.extend(["", "## Reçu", ""])
    lines.append(f"Empreinte de ce permis : `{digest}`.")
    if signed and signer_id:
        lines.append(f"Signé par `{_cell(signer_id)}` (ed25519), via un reçu p2r.")
        lines.append("Vérifier le JSON : `permis verifier <fichier.json>`.")
        lines.append(
            "Sans clef publique transmise à part, la vérification dit seulement que le fichier "
            "n'a pas changé depuis la signature faite avec la clef qu'il contient."
        )
    else:
        lines.append("Non signé. Pour un reçu vérifiable : `permis analyse … --signer clef.json`.")
    lines.extend(["", "## Limites", ""])
    for item in permis["limits"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _agents(count: int) -> str:
    if count == 0:
        return "aucune IA décisionnelle"
    if count == 1:
        return "1 IA décisionnelle"
    return f"{count} IA décisionnelles"


def _summary(summary: dict) -> str:
    return " · ".join(
        [
            _count(summary.get("BLOQUER", 0), "effet à bloquer sans validation humaine", "effets à bloquer sans validation humaine"),
            _count(summary.get("INCONNU", 0), "inconnu", "inconnus"),
            _count(summary.get("À SURVEILLER", 0), "à surveiller", "à surveiller"),
            _count(summary.get("AUTORISÉ", 0), "lecture autorisée", "lectures autorisées"),
        ]
    )


def _count(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _cell(value: object) -> str:
    return str(value).replace("|", "/").replace("\n", " ")
