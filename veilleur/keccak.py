"""Keccak-256 en Python pur — pour que le vérificateur n'ait **aucune dépendance**.

Pourquoi
--------
Le veilleur doit pouvoir tourner chez un tiers sans rien de notre infrastructure. Une dépendance
externe en est une : `pycryptodome` n'est pas installé partout, et une vérification qui échoue à
l'import n'est pas une vérification reproductible. Or tout le veilleur repose sur `keccak256` —
`topic0`, sélecteurs, feuilles, nœuds de l'arbre.

Cette implémentation est donc la **repli garanti**. Quand `pycryptodome` est présent, c'est lui qui
sert (il est plus rapide) ; sinon celle-ci prend le relais, et le résultat est le même.

KE#119 : réimplémenter un vérificateur exige un test DIFFÉRENTIEL sur entrées adverses, pas un test
de cohérence interne. `bench/test_keccak.py` confronte cette implémentation à `pycryptodome` sur des
centaines d'entrées, aux vecteurs connus de Keccak-256, et **aux données réelles du projet** — les
67 signatures d'événements et les feuilles de l'oracle. L'invariant n'est pas « ça a l'air de
marcher », c'est « même sortie que la référence, octet pour octet, sur tout l'échantillon ».

Keccak-256 « original » (padding `0x01`), pas SHA3-256 (padding `0x06`) : c'est celui d'Ethereum, et
confondre les deux donne des empreintes parfaitement plausibles et parfaitement fausses.
"""
_MASK = (1 << 64) - 1

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(a):
    for rc in _ROUND_CONSTANTS:
        # θ
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # ρ et π
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROTATIONS[x][y])
        # χ
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK) & b[(x + 2) % 5][y])
        # ι
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    """Keccak-256 d'Ethereum. Rend 32 octets."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("keccak256 attend des octets.")
    data = bytes(data)
    rate = 136                                   # 1600 − 2×256 bits, en octets
    # Padding multi-rate « pad10*1 » avec le premier octet 0x01 : c'est Keccak ORIGINAL.
    # SHA3-256 utiliserait 0x06 et donnerait un résultat différent, plausible et faux.
    pad_len = rate - (len(data) % rate)
    if pad_len == 1:
        padded = data + b"\x81"                  # les deux bits de padding tombent sur le même octet
    else:
        padded = data + b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"

    a = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            a[i % 5][i // 5] ^= lane
        a = _keccak_f(a)

    out = b""
    for i in range(4):                            # 4 lanes × 8 octets = 32 octets
        out += (a[i % 5][i // 5]).to_bytes(8, "little")
    if len(out) != 32:
        raise RuntimeError("ARRÊT : keccak256 n'a pas produit 32 octets.")
    return out
