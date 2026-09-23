"""Clé d'attestation du veilleur — **Ed25519**, et ce choix est constitutif.

Le veilleur doit signer ses feux verts, mais il ne doit pas pouvoir signer une transaction. Une clé
secp256k1 le pourrait : rien dans le code n'empêcherait quelqu'un de la réutiliser pour émettre une
transaction EVM. Une clé Ed25519 ne le peut pas — pas « ne devrait pas », ne PEUT pas : l'EVM ne
reconnaît aucune signature Ed25519, il n'existe aucun chemin qui transforme cette clé en pouvoir
on-chain. Ce qui vérifie ne doit pas pouvoir signer ; ici, c'est une propriété de l'algorithme, pas
une promesse d'exploitation.

Le secret ne transite JAMAIS par la ligne de commande (KE#107 / fuite `VERCEL_TOKEN` du 2026-09-11) :
`.env` nomme un CHEMIN de fichier, et ce module lit le fichier lui-même. Les hints d'erreur des
outils réimpriment la commande, jetons compris — donc on ne met pas de jeton dans une commande.
"""
import os
import re
import stat

_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")


class AttestError(RuntimeError):
    pass


def _ed25519():
    """Import TARDIF : la vérification publique ne signe rien et ne doit donc pas exiger
    `cryptography`. Une dépendance qu'on n'utilise pas ne doit pas empêcher de vérifier."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                                       Ed25519PublicKey)
    except ImportError as e:                            # pragma: no cover - dépend de la machine
        raise AttestError(
            "ARRÊT : `cryptography` est absent, donc aucune signature ne peut être produite NI "
            "vérifiée. Le mode « vérifier-publiquement » n'en a pas besoin ; l'attestation, si."
        ) from e
    return InvalidSignature, _ser, Ed25519PrivateKey, Ed25519PublicKey


class AttestKey:
    def __init__(self, private_bytes: bytes):
        if len(private_bytes) != 32:
            raise AttestError("ARRÊT : une clé Ed25519 fait 32 octets.")
        _, _, Priv, _pub = _ed25519()
        self._k = Priv.from_private_bytes(private_bytes)

    @property
    def public_hex(self):
        _, ser, _, _ = _ed25519()
        return self._k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> bytes:
        return self._k.sign(message)

    # ------------------------------------------------------------------ fichier

    @classmethod
    def generate(cls, path):
        if os.path.exists(path):
            raise AttestError(
                f"ARRÊT : {path} existe déjà. Écraser une clé d'attestation invaliderait tous les feux "
                f"verts déjà émis sous l'ancienne clé — on ne le fait jamais par effet de bord.")
        _, ser, Priv, _pub = _ed25519()
        k = Priv.generate()
        raw = k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(raw.hex() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return cls(raw)

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            raise AttestError(
                f"ARRÊT : clé d'attestation absente ({path}). Un veilleur qui ne peut pas signer ne "
                f"produit PAS un feu vert non signé : il refuse.")
        st = os.stat(path)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise AttestError(
                f"ARRÊT : {path} est lisible par le groupe ou par tous (mode {oct(st.st_mode & 0o777)}). "
                f"`chmod 600` avant de continuer.")
        with open(path, "r", encoding="utf-8") as fh:
            txt = fh.read().strip()
        if not _HEX32.match(txt):
            raise AttestError(f"ARRÊT : {path} ne contient pas 32 octets en hexadécimal.")
        return cls(bytes.fromhex(txt))


def verify(public_hex: str, message: bytes, signature: bytes) -> bool:
    """Vérification, utilisable par quiconque — y compris hors de ce dépôt."""
    if not _HEX32.match(public_hex or ""):
        raise AttestError("ARRÊT : clé publique attendue en 32 octets hexadécimaux.")
    InvalidSignature, _ser2, _priv, Pub = _ed25519()
    pk = Pub.from_public_bytes(bytes.fromhex(public_hex))
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
