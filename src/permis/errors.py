"""Erreurs lisibles par l'appelant, sans valeur secrète dans le message."""


class PermisError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)

    def __str__(self) -> str:
        return f"{self.code}: {super().__str__()}"
