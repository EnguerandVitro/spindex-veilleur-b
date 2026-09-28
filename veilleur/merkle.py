"""Arbre merkle à la convention de `SpindexRewards` (§9 / §12.1 / §20), et rien d'autre.

**Ce module ne décrit plus la convention : il la LIT, et il REFUSE DE SE CHARGER si elle a
bougé.** C'est le correctif du défaut relevé par l'atelier Rewards : la convention était
recopiée EN PROSE dans cette docstring, `rewards_constants.json` n'était lu nulle part, et il
n'existait donc aucun arrêt bruyant. Le jour où la séparation de domaine est entrée dans le
contrat, ce module aurait continué à calculer des feuilles périmées — et les contrôles `PW-A`
et `OD-A` auraient rapporté « la racine publiée ne correspond pas à la table », c'est-à-dire
une divergence de RACINE imputée à l'exploitant, alors que le défaut était une obsolescence
de MODULE. Un veilleur qui accuse à tort est pire qu'un veilleur muet.

Ce que la convention dit, tel qu'il est vérifié au chargement par `convention.charger()` :
  - feuille : `keccak256(bytes.concat(keccak256(abi.encode(TAG, …))))` — DOUBLE hachage (une
    preuve de 64 octets ne peut pas être relue comme une feuille) ET **étiquette de domaine
    en PREMIER MOT** de chaque préimage ;
  - nœud   : `keccak256(min(a,b) ‖ max(a,b))` — PAIRES TRIÉES ;
  - niveau impair : dernier nœud PROMU TEL QUEL, jamais dupliqué.

Les étiquettes (`TAG_CLAIM`, `TAG_DRAW`) ne sont pas transcrites ici : elles viennent de
`rewards_constants.json`, et leur empreinte y est confrontée au keccak de leur préimage citée
(KE#130 / KE#119). La table canonique côté contrat reste `SpindexRewards.domainTags()`.

Ce module reste un RÉIMPLÉMENTEUR DE VÉRIFICATEUR (KE#119) : il est donc soumis à un test
DIFFÉRENTIEL contre les racines produites par `MerkleBuilder.sol`, sur des cardinaux pairs ET
impairs (`bench/test_merkle.py`), et l'invariant n'est pas « même résultat sur un cas » mais
« même racine sur tout l'échantillon, y compris les cardinaux impairs où se joue la promotion
du nœud orphelin ».
"""
from . import convention as _convention
from .chainabi import keccak256, enc_address, enc_uint


class MerkleError(RuntimeError):
    pass


# ── ARRÊT AU CHARGEMENT ──────────────────────────────────────────────────────────────────
# Si la convention scellée n'est plus celle de ce module, l'import lève. C'est voulu : un
# module de calcul de feuilles qui se charge à moitié calcule des feuilles à moitié fausses,
# et le contrôle qui les compare accuse l'exploitant. `convention.py` ne lève RIEN à l'import,
# de sorte que `outils/faire_lot_public.py` — l'outil qui RÉPARE un lot périmé — reste
# importable même quand ce module-ci refuse (KE#105 : ne pas murer le chemin de réparation).
CONVENTION = _convention.defaut()
TAG_CLAIM = CONVENTION.tag("claim")
TAG_DRAW = CONVENTION.tag("draw")


def _enc_bytes32(b: bytes) -> bytes:
    if not isinstance(b, (bytes, bytearray)) or len(bytes(b)) != 32:
        raise MerkleError(f"ARRÊT : étiquette de domaine qui n'est pas un mot de 32 octets : {b!r}")
    return bytes(b)


def leaf_week(player: str, week_id: int, rakeback_usdg: int, revshare_usdg: int) -> bytes:
    """Feuille de l'arbre de PAIEMENT hebdomadaire.

    `keccak256(bytes.concat(keccak256(abi.encode(TAG_CLAIM, address, uint256, uint256,
    uint256))))`. L'étiquette est le PREMIER mot : sans elle, cette feuille est bit pour bit
    la feuille de saison de l'indexeur (même forme ABI, même double keccak) — défaut F03.
    """
    inner = keccak256(_enc_bytes32(TAG_CLAIM) + enc_address(player) + enc_uint(week_id)
                      + enc_uint(rakeback_usdg) + enc_uint(revshare_usdg))
    return keccak256(inner)


def leaf_draw(player: str, week_id: int, index: int, cumulative_from: int,
              cumulative_to: int) -> bytes:
    """Feuille de l'arbre des POIDS de tirage.

    `abi.encode(TAG_DRAW, address player, uint256 weekId, uint256 index, uint256 from,
    uint256 to)`.
    """
    inner = keccak256(_enc_bytes32(TAG_DRAW) + enc_address(player) + enc_uint(week_id)
                      + enc_uint(index) + enc_uint(cumulative_from) + enc_uint(cumulative_to))
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
