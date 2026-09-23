"""Tout ce qui vient du contrat se LIT dans le contrat : ABI, `topic0`, constantes, sélecteurs.

Trois sources, et elles se contrôlent l'une l'autre :

1. l'ABI compilée (`contracts/out/SpindexRewards.sol/SpindexRewards.json`), dont la FRAÎCHEUR est
   vérifiée contre le `keccak256` de la source déclaré dans `metadata.sources` — si l'ABI a été
   compilée sur une autre version du contrat, on s'arrête ;
2. la SOURCE elle-même, d'où sont extraites les constantes de boost (`BOOST_ONE`, `BOOST_RAMP`,
   `BOOST_CAP_ELAPSED`) : le veilleur doit rejouer `_boost` à l'identique, et recopier `30 days` à la
   main serait exactement la constante recopiée que la règle interdit ;
3. `contracts/rewards/rewards_constants.json`, fichier SCELLÉ produit par l'atelier de référence.

Les valeurs (2) et (3) sont comparées : une divergence entre la source et le fichier scellé est un
ARRÊT, pas un avertissement. Deux artefacts indépendants qui disent la même chose valent mieux qu'un
seul qu'on croit sur parole.
"""
import hashlib
import json
import os
import re

from . import artefacts as _artefacts

from . import keccak as _keccak_pur

# `pycryptodome` quand il est là (plus rapide), l'implémentation pure sinon. Le vérificateur doit
# pouvoir tourner chez un tiers SANS dépendance : une vérification qui échoue à l'import n'est pas
# une vérification reproductible. Les deux chemins sont confrontés l'un à l'autre par le banc
# (`test_keccak.py`), sur les vecteurs connus ET sur les données réelles du projet.
try:
    from Crypto.Hash import keccak as _keccak_rapide
except ImportError:                                     # pragma: no cover - dépend de la machine
    _keccak_rapide = None

IMPLEMENTATION_KECCAK = "pycryptodome" if _keccak_rapide else "python pur (repli sans dépendance)"


def keccak256(data: bytes) -> bytes:
    if _keccak_rapide is not None:
        h = _keccak_rapide.new(digest_bits=256)
        h.update(data)
        return h.digest()
    return _keccak_pur.keccak256(data)


class AbiError(RuntimeError):
    pass


# ---------------------------------------------------------------------- chargement

def _canonical(inp):
    t = inp["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_canonical(c) for c in inp["components"]) + ")" + t[len("tuple"):]
    return t


class ContractAbi:
    """ABI d'un contrat, avec ses `topic0` et ses sélecteurs, dérivés — jamais recopiés.

    `racine` est soit l'arbre `contracts/`, soit un LOT PUBLIÉ (voir `artefacts.py`). Les contrôles
    sont les mêmes dans les deux cas : le `keccak256` de la source est confronté à celui que l'ABI
    déclare, et une divergence est un ARRÊT — décoder avec la mauvaise ABI se trompe EN SILENCE.
    """

    def __init__(self, racine, name):
        art = _artefacts.resoudre(racine, name)
        abi, declared = art.charger_abi()
        raw = open(art.source_path, "rb").read()
        got = "0x" + keccak256(raw).hex()
        if got != declared:
            raise AbiError(
                f"ARRÊT : l'ABI de {name} a été compilée sur une AUTRE source (déclaré {declared} != "
                f"fichier {got}). Un veilleur qui décode avec la mauvaise ABI se trompe EN SILENCE.")
        self.artefacts = art
        self.name = name
        self.abi = abi
        self.source = raw.decode("utf-8")
        self.source_sha256 = hashlib.sha256(raw).hexdigest()

        self.events = {}
        for e in self.abi:
            if e.get("type") != "event":
                continue
            sig = "%s(%s)" % (e["name"], ",".join(_canonical(i) for i in e["inputs"]))
            self.events[e["name"]] = {
                "signature": sig,
                "topic0": "0x" + keccak256(sig.encode()).hex(),
                "inputs": e["inputs"],
            }
        if not self.events:
            raise AbiError(f"ARRÊT : aucun événement dans l'ABI de {name} — cardinal nul (KE#111).")

        self.functions = {}
        for f in self.abi:
            if f.get("type") != "function":
                continue
            sig = "%s(%s)" % (f["name"], ",".join(_canonical(i) for i in f["inputs"]))
            self.functions[f["name"]] = {
                "signature": sig,
                "selector": keccak256(sig.encode())[:4],
                "inputs": f["inputs"],
                "outputs": f.get("outputs", []),
            }

    def topic0(self, event_name):
        if event_name not in self.events:
            raise AbiError(f"ARRÊT : {self.name} n'a pas d'événement « {event_name} ».")
        return self.events[event_name]["topic0"]

    def selector(self, fn):
        if fn not in self.functions:
            raise AbiError(f"ARRÊT : {self.name} n'a pas de fonction « {fn} ».")
        return self.functions[fn]["selector"]


# ---------------------------------------------------------------------- décodage d'événements

_UINT = re.compile(r"^uint(\d+)$")
_INT = re.compile(r"^int(\d+)$")


def _decode_word(word: bytes, typ: str):
    if typ == "address":
        return "0x" + word[12:].hex()
    if typ == "bool":
        return int.from_bytes(word, "big") != 0
    if typ.startswith("bytes") and typ != "bytes":
        n = int(typ[5:])
        return "0x" + word[:n].hex()
    if _UINT.match(typ):
        return int.from_bytes(word, "big")
    if _INT.match(typ):
        v = int.from_bytes(word, "big")
        bits = int(_INT.match(typ).group(1))
        return v - (1 << bits) if v >= (1 << (bits - 1)) else v
    raise AbiError(f"ARRÊT : type « {typ} » non statique ou inconnu — le veilleur refuse de deviner.")


def decode_event(abi: ContractAbi, event_name: str, log: dict) -> dict:
    """Décode un journal selon l'ABI. TOUS les événements consommés par le veilleur sont statiques :
    un type dynamique fait ÉCHOUER le décodage au lieu de rendre une valeur plausible."""
    spec = abi.events[event_name]
    if log["topics"][0].lower() != spec["topic0"].lower():
        raise AbiError(
            f"ARRÊT : topic0 {log['topics'][0]} ne correspond pas à {event_name} ({spec['topic0']}). "
            f"Quatre topic0 sont PARTAGÉS entre contrats : ne jamais filtrer par topic0 seul.")
    out = {}
    data = bytes.fromhex(log["data"][2:]) if log.get("data", "0x") != "0x" else b""
    ti, di = 1, 0
    for inp in spec["inputs"]:
        t = _canonical(inp)
        if inp.get("indexed"):
            word = bytes.fromhex(log["topics"][ti][2:])
            ti += 1
            out[inp["name"]] = _decode_word(word, t)
        else:
            word = data[di * 32:(di + 1) * 32]
            if len(word) != 32:
                raise AbiError(f"ARRÊT : données trop courtes pour {event_name}.{inp['name']}.")
            di += 1
            out[inp["name"]] = _decode_word(word, t)
    if di * 32 != len(data):
        raise AbiError(
            f"ARRÊT : {event_name} porte {len(data)} octets de données pour {di * 32} attendus. "
            f"Décoder un journal plus long que prévu, c'est décoder faux en silence.")
    return out


# ---------------------------------------------------------------------- encodage d'appels

def enc_address(a: str) -> bytes:
    return bytes.fromhex(a[2:].rjust(40, "0")).rjust(32, b"\x00")


def enc_uint(v: int) -> bytes:
    if v < 0 or v >= (1 << 256):
        raise AbiError("ARRÊT : entier hors domaine uint256.")
    return v.to_bytes(32, "big")


def encode_call(abi: ContractAbi, fn: str, args) -> str:
    spec = abi.functions[fn]
    if len(args) != len(spec["inputs"]):
        raise AbiError(f"ARRÊT : {fn} attend {len(spec['inputs'])} arguments, {len(args)} fournis.")
    body = b""
    for inp, v in zip(spec["inputs"], args):
        t = _canonical(inp)
        if t == "address":
            body += enc_address(v)
        elif _UINT.match(t):
            body += enc_uint(int(v))
        else:
            raise AbiError(f"ARRÊT : argument de type « {t} » non pris en charge par cet encodeur minimal.")
    return "0x" + (spec["selector"] + body).hex()


def _static_words(inp) -> int:
    """Nombre de mots de 32 octets occupés par un type STATIQUE. Un type dynamique lève."""
    t = inp["type"]
    if t.startswith("tuple"):
        if t != "tuple":
            raise AbiError(f"ARRÊT : tableau de tuples « {t} » non pris en charge.")
        return sum(_static_words(c) for c in inp["components"])
    if t in ("bytes", "string") or t.endswith("[]"):
        raise AbiError(f"ARRÊT : type dynamique « {t} » — le décodeur du veilleur refuse de deviner.")
    return 1


def _decode_static(inp, data: bytes, off: int):
    t = inp["type"]
    if t.startswith("tuple"):
        out = {}
        p = off
        for c in inp["components"]:
            v, p = _decode_static(c, data, p)
            out[c.get("name") or f"_{len(out)}"] = v
        return out, p
    return _decode_word(data[off:off + 32], _canonical(inp)), off + 32


def decode_outputs(abi: ContractAbi, fn: str, raw_hex: str):
    """Décode un retour d'`eth_call`. Types statiques uniquement, structures statiques comprises."""
    spec = abi.functions[fn]
    data = bytes.fromhex(raw_hex[2:]) if raw_hex and raw_hex != "0x" else b""
    outs = spec["outputs"]
    if not outs:
        raise AbiError(f"ARRÊT : {fn} ne rend rien — rien à décoder.")
    need = 32 * sum(_static_words(o) for o in outs)
    if len(data) < need:
        raise AbiError(
            f"ARRÊT : retour de {fn} trop court ({len(data)} o pour {need} attendus). "
            f"Un retour vide n'est PAS un zéro (KE#105).")
    vals = []
    p = 0
    for o in outs:
        v, p = _decode_static(o, data, p)
        vals.append(v)
    return vals[0] if len(vals) == 1 else vals


# ---------------------------------------------------------------------- Multicall3

SEL_AGGREGATE3 = keccak256(b"aggregate3((address,bool,bytes)[])")[:4]


def encode_aggregate3(calls):
    """`aggregate3(Call3[])` encodé à la main. `calls` = [(target, allowFailure, data_bytes)]."""
    if not calls:
        raise AbiError("ARRÊT : aggregate3 sans sous-appel — un lot vide rendrait un résultat vide crédible.")
    n = len(calls)
    struct_offsets = b""
    structs = b""
    base = 32 * n
    for target, allow, data in calls:
        s = enc_address(target)
        s += (1 if allow else 0).to_bytes(32, "big")
        s += (96).to_bytes(32, "big")
        s += len(data).to_bytes(32, "big")
        s += data + b"\x00" * ((-len(data)) % 32)
        struct_offsets += (base + len(structs)).to_bytes(32, "big")
        structs += s
    head = (32).to_bytes(32, "big") + n.to_bytes(32, "big")
    return "0x" + (SEL_AGGREGATE3 + head + struct_offsets + structs).hex()


def decode_aggregate3(raw_hex: str, expected_n: int):
    """Décode `(bool success, bytes returnData)[]`. Assertion de CARDINAL : le nombre de résultats DOIT
    égaler le nombre de sous-appels. Un lot tronqué ne doit pas rendre une liste courte crédible."""
    data = bytes.fromhex(raw_hex[2:]) if raw_hex and raw_hex != "0x" else b""
    if len(data) < 64:
        raise AbiError("ARRÊT : réponse aggregate3 trop courte.")
    off = int.from_bytes(data[0:32], "big")
    n = int.from_bytes(data[off:off + 32], "big")
    if n != expected_n:
        raise AbiError(
            f"ARRÊT : aggregate3 a rendu {n} résultats pour {expected_n} sous-appels. "
            f"Un lot tronqué fausserait toutes les comparaisons en aval (KE#111).")
    out = []
    tbl = off + 32
    for i in range(n):
        rel = int.from_bytes(data[tbl + 32 * i:tbl + 32 * (i + 1)], "big")
        p = tbl + rel
        success = int.from_bytes(data[p:p + 32], "big") != 0
        boff = int.from_bytes(data[p + 32:p + 64], "big")
        q = p + boff
        blen = int.from_bytes(data[q:q + 32], "big")
        ret = data[q + 32:q + 32 + blen]
        out.append((success, "0x" + ret.hex()))
    if len(out) != expected_n:
        raise AbiError("ARRÊT : cardinal des résultats aggregate3 incohérent après décodage.")
    return out


# ---------------------------------------------------------------------- constantes lues dans la SOURCE

_CONST = re.compile(
    r"uint256\s+(?:public|internal|private)\s+constant\s+([A-Z_0-9]+)\s*=\s*([^;]+);")

_UNITS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}


def _eval_solidity_literal(expr: str) -> int:
    e = expr.strip().replace("_", "")
    m = re.fullmatch(r"(\d+)\s*(seconds|minutes|hours|days|weeks)", e)
    if m:
        return int(m.group(1)) * _UNITS[m.group(2)]
    m = re.fullmatch(r"(\d+)e(\d+)", e)
    if m:
        return int(m.group(1)) * 10 ** int(m.group(2))
    m = re.fullmatch(r"(\d+)", e)
    if m:
        return int(e)
    raise AbiError(f"ARRÊT : littéral Solidity « {expr} » non interprétable. Ne jamais deviner une constante.")


def source_constants(abi: ContractAbi, names):
    """Extrait des constantes `uint256 ... constant NAME = <littéral>;` de la SOURCE."""
    found = {}
    for m in _CONST.finditer(abi.source):
        if m.group(1) in names:
            found[m.group(1)] = _eval_solidity_literal(m.group(2))
    missing = [n for n in names if n not in found]
    if missing:
        raise AbiError(
            f"ARRÊT : constantes introuvables dans {abi.name}.sol : {', '.join(missing)}. "
            f"Le veilleur ne les recopie pas de mémoire.")
    if len(found) != len(set(names)):
        raise AbiError("ARRÊT : cardinal des constantes extraites incohérent (KE#111).")
    return found


class RewardsModel:
    """Constantes et formules de `SpindexRewards`, lues dans la source et RECOUPÉES avec le fichier scellé."""

    NEEDED = ("BOOST_ONE", "BOOST_MAX", "BOOST_RAMP", "BOOST_CAP_ELAPSED", "EXIT_BURN_BPS", "BPS",
              "CLAIM_WINDOW", "PRIZE_WINDOW")

    # nom dans la source -> clé du fichier scellé `rewards_constants.json`
    SEALED_MAP = {
        "BOOST_ONE": "boost_scale",
        "BOOST_MAX": "boost_max",
        "BOOST_RAMP": "boost_step_s",
        "BOOST_CAP_ELAPSED": "boost_cap_s",
        "EXIT_BURN_BPS": "exit_burn_bps",
        "BPS": "bps",
        "CLAIM_WINDOW": "claim_window_s",
        "PRIZE_WINDOW": "draw_claim_window_s",
    }

    def __init__(self, racine=None):
        racine = racine or _artefacts.racine_par_defaut()
        self.abi = ContractAbi(racine, "SpindexRewards")
        self.c = source_constants(self.abi, self.NEEDED)
        sealed_path = self.abi.artefacts.constants_path
        if not os.path.exists(sealed_path):
            raise AbiError(f"ARRÊT : {sealed_path} absent — le recoupement des constantes est impossible.")
        sealed = json.load(open(sealed_path, encoding="utf-8"))
        self.sealed = sealed
        diverge = []
        for src_name, sealed_key in self.SEALED_MAP.items():
            if sealed_key not in sealed:
                diverge.append((src_name, sealed_key, self.c[src_name], "ABSENT du fichier scellé"))
            elif int(sealed[sealed_key]) != self.c[src_name]:
                diverge.append((src_name, sealed_key, self.c[src_name], sealed[sealed_key]))
        if diverge:
            lines = "\n".join(f"  {a} (source) = {c}  !=  {b} (scellé) = {d}" for a, b, c, d in diverge)
            raise AbiError(
                "ARRÊT : la SOURCE et le fichier scellé `rewards_constants.json` ne disent pas la même "
                f"chose. On ne choisit pas entre deux autorités, on s'arrête.\n{lines}")
        # Le contrat lui-même vérifie cette identité à la construction ; on la rejoue.
        if self.c["BOOST_ONE"] + self.c["BOOST_ONE"] * self.c["BOOST_CAP_ELAPSED"] // self.c["BOOST_RAMP"] \
                != self.c["BOOST_MAX"]:
            raise AbiError("ARRÊT : BOOST_ONE + BOOST_ONE × CAP / RAMP != BOOST_MAX — constantes incohérentes.")

        mk = sealed.get("merkle") or {}
        # La convention merkle est SCELLÉE : si elle change, mon constructeur d'arbre devient faux.
        want = {
            "node": "keccak256(a < b ? a||b : b||a)  — paires triées",
            "odd_node": "promu tel quel, JAMAIS dupliqué",
            "leaf": "keccak256(bytes.concat(keccak256(abi.encode(...))))",
        }
        for k, v in want.items():
            if mk.get(k) != v:
                raise AbiError(
                    f"ARRÊT : convention merkle scellée modifiée ({k}). Mon constructeur d'arbre a été écrit "
                    f"pour « {v} » et lit « {mk.get(k)} ». Relire §9/§20 avant de continuer.")

    # ---------------- formules du contrat, rejouées à l'identique

    def boost(self, anchor: int, ts: int) -> int:
        """`_boost` de `SpindexRewards.sol`, division ENTIÈRE comprise."""
        one = self.c["BOOST_ONE"]
        if anchor == 0 or ts <= anchor:
            return one
        e = ts - anchor
        if e > self.c["BOOST_CAP_ELAPSED"]:
            e = self.c["BOOST_CAP_ELAPSED"]
        return one + one * e // self.c["BOOST_RAMP"]

    def effective_stake(self, amount: int, anchor: int, ts: int) -> int:
        """`effectiveStakeOf` : 0 si le montant est nul, sinon montant × boost / BOOST_ONE."""
        if amount == 0:
            return 0
        return amount * self.boost(anchor, ts) // self.c["BOOST_ONE"]

    def halved_anchor(self, amount: int, anchor: int, ts: int):
        """`_halveBoost` : rend la NOUVELLE ancre, ou None si le contrat n'aurait RIEN émis.

        Le `None` est le piège n°2 de l'atelier 0 : un joueur déjà à ×1 récolte son rakeback sans
        qu'aucun `BoostHalved` ne soit émis. Un indexeur qui halverait sur `Claimed` sans répliquer ce
        garde-fou divergerait exactement là."""
        one = self.c["BOOST_ONE"]
        if amount == 0 or anchor == 0:
            return None
        nb = self.boost(anchor, ts) // 2
        if nb < one:
            nb = one
        e = (nb - one) * self.c["BOOST_RAMP"] // one
        new_anchor = ts - e
        if new_anchor <= anchor:
            return None
        return new_anchor
