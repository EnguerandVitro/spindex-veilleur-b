"""Chargement et validation de forme des tables publiées par l'exploitant (arbitrage Q1).

Emplacement : `<SPINDEX_TABLES_BASE_URL>/<type>-<weekId>.json`, ou un chemin local pour le banc.

Trois refus de forme qui ne se négocient pas :

1. **`snapshotBlock` obligatoire.** Sans lui, le contrôle d'exhaustivité n'a même pas de bloc où lire.
   C'est la toute première chose que le veilleur refuse.
2. **Tout `uint256` est une CHAÎNE décimale.** Un entier JSON au-delà de 2⁵³ est relu comme un flottant
   et ment en silence : un poids de `1000000000000000000001` devient `1e21`, l'arbre change, et le
   diagnostic serait « racine non concordante » sans jamais nommer la cause. Un nombre JSON dans un
   champ de montant est donc un ARRÊT, pas une conversion silencieuse.
3. **Aucun flottant nulle part.** Même raison, un cran plus haut.

Et deux refus de fond, qui ne sont pas de la forme mais de la sécurité :
   - aucune feuille en DOUBLE (exactement la même feuille deux fois) ;
   - aucun joueur en double dans une table de semaine (deux feuilles pour un même joueur = un double
     paiement ; le contrat n'autorise qu'un `claim` par joueur et par semaine, donc la seconde feuille
     serait de l'argent immobilisé au mieux, une préparation de vol au pire).
"""
import hashlib
import json
import os
import re
import urllib.request

_DEC = re.compile(r"^(0|[1-9][0-9]*)$")


class TableError(RuntimeError):
    """Refus de table. TOUJOURS bruyant (KE#105)."""


def _no_float(x):
    raise TableError("ARRÊT : la table contient un nombre à virgule. Aucune valeur de cette table ne peut "
                     "être un flottant — un flottant ment en silence au-delà de 2⁵³.")


def _parse_strict(raw_text: str):
    """`json.loads` qui REFUSE les flottants, et qui marque les entiers pour qu'on puisse les rejeter
    là où la spec exige une chaîne."""
    return json.loads(raw_text, parse_float=_no_float, parse_constant=_no_float)


def _u256(obj, key, where):
    v = obj.get(key)
    if isinstance(v, bool) or isinstance(v, int):
        raise TableError(
            f"ARRÊT : {where}.{key} est un NOMBRE JSON. Tout uint256 doit être une chaîne décimale "
            f"(au-delà de 2⁵³ un nombre JSON est relu en flottant et ment en silence).")
    if not isinstance(v, str) or not _DEC.match(v):
        raise TableError(f"ARRÊT : {where}.{key} n'est pas une chaîne décimale (lu : {v!r}).")
    n = int(v)
    if n >= 1 << 256:
        raise TableError(f"ARRÊT : {where}.{key} dépasse uint256.")
    return n


def _small_int(obj, key, where):
    v = obj.get(key)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise TableError(f"ARRÊT : {where}.{key} doit être un entier JSON positif (lu : {v!r}).")
    return v


def _addr(obj, key, where):
    v = obj.get(key)
    if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
        raise TableError(f"ARRÊT : {where}.{key} n'est pas une adresse (lu : {v!r}).")
    return v.lower()


def _bytes32(obj, key, where):
    v = obj.get(key)
    if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", v):
        raise TableError(f"ARRÊT : {where}.{key} n'est pas un bytes32 0x + 64 hexa (lu : {v!r}).")
    return bytes.fromhex(v[2:])


class Table:
    prize_token = None                        # tables de tirage seulement
    prize_amount = None

    def __init__(self, kind, week_id, snapshot_block, root, total, leaf_count, leaves, raw_bytes, origin):
        self.kind = kind                      # "week" | "draw"
        self.week_id = week_id
        self.snapshot_block = snapshot_block
        self.root = root                      # bytes32 annoncée
        self.total = total                    # totalUsdg (week) ou totalWeight (draw)
        self.leaf_count = leaf_count
        self.leaves = leaves                  # liste de dicts normalisés
        self.raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.raw_bytes = raw_bytes
        self.origin = origin

    @property
    def players(self):
        return [lf["player"] for lf in self.leaves]


def fetch_raw(base_url_or_path: str, kind: str, week_id: int, timeout=30) -> tuple:
    """Rend (octets, origine). Un emplacement distant DOIT être https : une table servie en clair est
    modifiable en vol, et le veilleur signerait alors la table de quelqu'un d'autre."""
    if kind not in ("week", "draw"):
        raise TableError(f"ARRÊT : type de table inconnu « {kind} ».")
    name = f"{kind}-{week_id}.json"
    if re.match(r"^https://", base_url_or_path):
        url = f"{base_url_or_path.rstrip('/')}/{name}"
        req = urllib.request.Request(url, headers={"user-agent": "spindex-veilleur/1 (read-only)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(), url
        except Exception as e:  # noqa: BLE001
            raise TableError(
                f"INDISPONIBLE : la table {url} n'a pas pu être lue ({e!r}). « Je n'ai pas pu vérifier » "
                f"n'est PAS « rien à signaler » — aucun feu vert ne sera écrit.") from e
    if re.match(r"^http://", base_url_or_path):
        raise TableError("ARRÊT : emplacement de table en HTTP clair refusé. Une table modifiable en vol "
                         "ferait signer au veilleur la table d'un tiers.")
    path = os.path.join(base_url_or_path, name)
    if not os.path.exists(path):
        raise TableError(
            f"INDISPONIBLE : la table {path} est absente. C'est un refus explicite, pas une heure calme.")
    with open(path, "rb") as fh:
        return fh.read(), path


def parse(raw_bytes: bytes, origin: str, expect_kind: str, expect_week_id: int) -> Table:
    try:
        doc = _parse_strict(raw_bytes.decode("utf-8"))
    except TableError:
        raise
    except Exception as e:  # noqa: BLE001
        raise TableError(f"ARRÊT : table illisible ({origin}) : {e!r}") from e
    if not isinstance(doc, dict):
        raise TableError("ARRÊT : la table n'est pas un objet JSON.")

    kind = doc.get("type")
    if kind != expect_kind:
        raise TableError(f"ARRÊT : table de type « {kind} », « {expect_kind} » attendu.")
    week_id = _u256(doc, "weekId", "table")
    if week_id != expect_week_id:
        raise TableError(f"ARRÊT : la table porte weekId={week_id}, {expect_week_id} demandé.")

    # (1) le refus qui vient en premier : sans bloc d'instantané, rien n'est vérifiable.
    if "snapshotBlock" not in doc:
        raise TableError(
            "ARRÊT : `snapshotBlock` absent de la table. C'est la PREMIÈRE chose que le veilleur refuse : "
            "sans bloc d'instantané, le contrôle d'exhaustivité n'a pas de bloc où lire, et la garantie "
            "de §21 n'est tenue par personne.")
    snapshot_block = _small_int(doc, "snapshotBlock", "table")
    if snapshot_block == 0:
        raise TableError("ARRÊT : `snapshotBlock` = 0 est impossible pour un instantané.")

    root = _bytes32(doc, "root", "table")
    total_key = "totalUsdg" if kind == "week" else "totalWeight"
    total = _u256(doc, total_key, "table")
    leaf_count = _small_int(doc, "leafCount", "table")

    leaves_raw = doc.get("leaves")
    if not isinstance(leaves_raw, list):
        raise TableError("ARRÊT : `leaves` absent ou n'est pas une liste.")
    # Assertion de CARDINAL (KE#111) : une table vide ferait passer racine et pavage « à vide ».
    if len(leaves_raw) == 0:
        raise TableError("ARRÊT : table à ZÉRO feuille. Un contrôle qui itère sur rien ne prouve rien.")
    if leaf_count != len(leaves_raw):
        raise TableError(
            f"ARRÊT : `leafCount` = {leaf_count} mais la table porte {len(leaves_raw)} feuilles.")

    leaves = []
    for i, lf in enumerate(leaves_raw):
        where = f"leaves[{i}]"
        if not isinstance(lf, dict):
            raise TableError(f"ARRÊT : {where} n'est pas un objet.")
        w = _u256(lf, "weekId", where)
        if w != week_id:
            raise TableError(f"ARRÊT : {where}.weekId = {w} != {week_id} de la table.")
        item = {"player": _addr(lf, "player", where), "weekId": w}
        if kind == "week":
            item["rakebackUsdg"] = _u256(lf, "rakebackUsdg", where)
            item["revshareUsdg"] = _u256(lf, "revshareUsdg", where)
        else:
            item["index"] = _u256(lf, "index", where)
            item["cumulativeFrom"] = _u256(lf, "cumulativeFrom", where)
            item["cumulativeTo"] = _u256(lf, "cumulativeTo", where)
        leaves.append(item)

    if len(leaves) != leaf_count:
        raise TableError("ARRÊT : cardinal des feuilles normalisées incohérent (KE#111).")

    # NOTE DE CONCEPTION — la détection des DOUBLONS n'est volontairement PAS ici.
    # Elle vit dans `controls.py` (PW-E / OD-E). Si elle refusait dès l'analyse syntaxique, le contrôle
    # correspondant serait inatteignable : un contrôle placé derrière une garde qui lève avant lui est du
    # code mort, tout vert et sans valeur (KE#69). Le veilleur doit pouvoir RENDRE un refus « feuille en
    # double » dans son verdict signé, pas seulement lever une exception d'analyse.

    t = Table(kind, week_id, snapshot_block, root, total, leaf_count, leaves, raw_bytes, origin)
    if kind == "draw":
        t.prize_token = _addr(doc, "prizeToken", "table")
        t.prize_amount = _u256(doc, "prizeAmount", "table")
    return t


def load(base_url_or_path: str, kind: str, week_id: int) -> Table:
    raw, origin = fetch_raw(base_url_or_path, kind, week_id)
    return parse(raw, origin, kind, week_id)


def archive(table: Table, state_dir: str) -> str:
    """Archive la table validée, telle quelle, avec son empreinte. C'est la seule trace qui permettra
    plus tard de rejouer un désaccord. Écriture ATOMIQUE (KE#112)."""
    d = os.path.join(state_dir, "tables")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{table.kind}-{table.week_id}-{table.raw_sha256[:16]}.json")
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(table.raw_bytes)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path
