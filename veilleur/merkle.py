"""Arbre merkle à la convention de `SpindexRewards` (§9 / §20), et rien d'autre.

Convention, lue dans `_verify` du contrat et dans la convention SCELLÉE de `rewards_constants.json` :
  - feuille : DOUBLE hachée — `keccak256(bytes.concat(keccak256(abi.encode(...))))`. Le double hachage
    sépare le domaine des feuilles de celui des nœuds internes : une preuve de 64 octets ne peut pas
    être réinterprétée en feuille valide ;
  - nœud   : `keccak256(min(a,b) ‖ max(a,b))` — PAIRES TRIÉES ;
  - niveau impair : le dernier nœud est PROMU TEL QUEL, **jamais dupliqué**. Dupliquer rendrait deux
    arbres distincts identiques, et c'est la forme classique qui casse l'unicité de la racine.

Ce module est réimplémenté en Python alors que `MerkleBuilder.sol` existe déjà : c'est donc un
RÉIMPLÉMENTEUR DE VÉRIFICATEUR (KE#119). Il est par conséquent soumis à un test DIFFÉRENTIEL contre
les racines produites par le Solidity, sur des cardinaux pairs ET impairs (`bench/test_merkle.py`),
et l'invariant n'est pas « même résultat sur un cas » mais « même racine sur tout l'échantillon, y
compris les cardinaux impairs où la promotion du nœud orphelin se joue ».
"""
from .chainabi import keccak256, enc_address, enc_uint


class MerkleError(RuntimeError):
    pass


def leaf_week(player: str, week_id: int, rakeback_usdg: int, revshare_usdg: int) -> bytes:
    """`keccak256(bytes.concat(keccak256(abi.encode(address, uint256, uint256, uint256))))`."""
    inner = keccak256(enc_address(player) + enc_uint(week_id) + enc_uint(rakeback_usdg)
                      + enc_uint(revshare_usdg))
    return keccak256(inner)


def leaf_draw(player: str, week_id: int, index: int, cumulative_from: int, cumulative_to: int) -> bytes:
    """`abi.encode(address player, uint256 weekId, uint256 index, uint256 from, uint256 to)`."""
    inner = keccak256(enc_address(player) + enc_uint(week_id) + enc_uint(index)
                      + enc_uint(cumulative_from) + enc_uint(cumulative_to))
    return keccak256(inner)


def hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak256(a + b) if a < b else keccak256(b + a)


def root(leaves) -> bytes:
    """Racine de l'arbre. `leaves` : liste de 32 octets, dans l'ORDRE de la table publiée."""
    if not leaves:
        raise MerkleError("ARRÊT : arbre sans feuille. Une racine calculée sur rien n'est pas une racine.")
    for i, x in enumerate(leaves):
        if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
            raise MerkleError(f"ARRÊT : feuille {i} n'est pas 32 octets.")
    level = list(leaves)
    n_levels = 0
    while len(level) > 1:
        up = []
        for k in range(0, len(level) - 1, 2):
            up.append(hash_pair(level[k], level[k + 1]))
        if len(level) % 2 == 1:
            up.append(level[-1])          # promu TEL QUEL, jamais dupliqué
        # Assertion de CARDINAL (KE#111) : un niveau doit faire exactement ⌈n/2⌉.
        if len(up) != (len(level) + 1) // 2:
            raise MerkleError("ARRÊT : cardinal de niveau incohérent — l'arbre est faux.")
        level = up
        n_levels += 1
        if n_levels > 256:
            raise MerkleError("ARRÊT : profondeur d'arbre aberrante.")
    return level[0]


def proof(leaves, index: int):
    """Preuve d'inclusion, même convention. Sert au banc et au recoupement, pas aux contrôles."""
    if index >= len(leaves):
        raise MerkleError("ARRÊT : index hors de la table.")
    level = list(leaves)
    i = index
    out = []
    while len(level) > 1:
        if i % 2 == 1:
            out.append(level[i - 1])
        elif i + 1 < len(level):
            out.append(level[i + 1])
        i //= 2
        up = [hash_pair(level[k], level[k + 1]) for k in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            up.append(level[-1])
        level = up
    return out


def verify(prf, rt: bytes, leaf: bytes) -> bool:
    """`_verify` du contrat, à l'identique."""
    h = leaf
    for p in prf:
        h = keccak256(h + p) if h < p else keccak256(p + h)
    return h == rt
