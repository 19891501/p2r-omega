"""Permis d'agir — lecture d'un workflow n8n et reçu vérifiable.

Le classement est une heuristique. Le reçu, quand il est demandé, s'appuie
sur les primitives de p2r (canonique, empreinte, identité d'effet, reçu signé).
Il atteste le document, pas la justesse du classement ni une exécution n8n.
"""

__version__ = "0.1.0"

from permis.analyze import analyze_path
from permis.sign import sign_envelope, verify_envelope

__all__ = ["__version__", "analyze_path", "sign_envelope", "verify_envelope"]
