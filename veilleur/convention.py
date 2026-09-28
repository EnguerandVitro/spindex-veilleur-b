"""La convention merkle **lue à sa source**, et le refus quand elle a bougé.

Pourquoi ce module existe
--------------------------
`merkle.py` portait la convention EN PROSE, dans sa docstring, et ne lisait
`rewards_constants.json` nulle part. Il n'avait donc **aucun arrêt bruyant** : le jour où la
séparation de domaine a été introduite dans le contrat, il a continué à calculer des feuilles
périmées, et les contrôles `PW-A` / `OD-A` auraient rapporté « la racine publiée ne correspond
pas à la table » — une divergence de RACINE, alors que le défaut était une **obsolescence de
module**. Le veilleur aurait accusé l'exploitant d'un défaut qui était le sien.

La règle est donc : rien de ce que le contrat décide n'est recopié ici. La convention, les
listes de champs et les étiquettes de domaine sont LUES dans `rewards_constants.json` (résolu
par `artefacts.py`, arbre `contracts/` chez nous ou lot publié chez un tiers), et chaque
étiquette est **recalculée depuis sa préimage citée** puis confrontée à l'empreinte citée
(KE#119 : un réimplémenteur se prouve par différentiel ; KE#130 : la référence vient de sa
source, jamais du sujet contrôlé).

Ce que le contrôle rend IMPOSSIBLE
-----------------------------------
La red team (F03) a exhibé une collision : sans étiquette, la feuille de saison de l'indexeur
et la feuille de PAIEMENT `claim` sont le MÊME mot — mêmes types ABI, même double keccak. Le
contrôle (c) ci-dessous refuse toute **signature de préimage** égale à celle d'un domaine de
paiement, ou préfixe de celle-ci. Il ne s'écarte pas de la collision, il la rend impossible :
avec deux étiquettes identiques, ou l'étiquette retirée des deux côtés, il rougit.

Ce module ne charge RIEN à l'import. C'est délibéré : `outils/faire_lot_public.py` — le seul
outil capable de RÉPARER un lot périmé — importe `chainabi`, qui importe ce module. Un refus
à l'import ici couperait la branche sur laquelle il est assis (KE#105 : un refus fermé qui
mure aussi le chemin de réparation). Le refus au chargement est porté par `merkle.py`, qui est
le module qui CALCULE, et par `RewardsModel`, qui est construit avant tout contrôle.
"""
import json
import os
import re

from . import artefacts as _artefacts
from .keccak import keccak256

# Domaines de PAIEMENT : ceux dont une feuille valide DÉPLACE DE L'ARGENT. Ce sont les deux
# entrées de la table canonique `SpindexRewards.domainTags()`.
DOMAINES_PAIEMENT = ("claim", "draw")

# Convention que CE veilleur implémente. Comparée mot pour mot au fichier scellé : un module
# qui implémente une convention et en affiche une autre est un mensonge silencieux.
CONVENTION_ATTENDUE = {
    "leaf": "keccak256(bytes.concat(keccak256(abi.encode(TAG, ...))))",
    "node": "keccak256(a < b ? a||b : b||a)  — paires triées",
    "odd_node": "promu tel quel, JAMAIS dupliqué",
    "claim_fields": [
        "bytes32 TAG_CLAIM",
        "address player",
        "uint256 weekId",
        "uint256 rakebackUsdg",
        "uint256 revshareUsdg",
    ],
    "draw_fields": [
        "bytes32 TAG_DRAW",
        "address player",
        "uint256 weekId",
        "uint256 index",
        "uint256 cumulativeFrom",
        "uint256 cumulativeTo",
    ],
}

_ETIQUETTE = re.compile(r'keccak256\("([^"]+)"\)\s*=\s*(0x[0-9a-fA-F]{64})')
_SUFFIXE = re.compile(r"_fields$")


class ConventionPerimee(RuntimeError):
    """La convention scellée n'est plus celle que ce veilleur implémente. Aucune feuille."""


class Convention:
    """Ce que le fichier scellé dit, une fois vérifié. Immuable en pratique."""

    __slots__ = ("chemin", "racine", "brut", "tags", "champs", "types", "domaines")

    def __init__(self, chemin, racine, brut, tags, champs, types, domaines):
        self.chemin, self.racine, self.brut = chemin, racine, brut
        self.tags, self.champs, self.types, self.domaines = tags, champs, types, domaines

    def tag(self, domaine: str) -> bytes:
        if domaine not in self.tags:
            raise ConventionPerimee(
                f"ARRÊT : domaine « {domaine} » absent de {self.chemin} "
                f"(déclarés : {sorted(self.tags)}). Une étiquette ne se devine pas.")
        return self.tags[domaine]

    def empreinte(self) -> str:
        """Empreinte des seules décisions qui changent une feuille. Sert à comparer deux
        racines d'artefacts sans comparer deux fichiers entiers (dont les champs de date)."""
        pieces = [self.brut.get(k, "") if not isinstance(self.brut.get(k), list)
                  else "|".join(self.brut[k]) for k in sorted(CONVENTION_ATTENDUE)]
        pieces += [f"{d}={self.tags[d].hex()}" for d in sorted(self.tags)]
        return keccak256("\x1f".join(str(p) for p in pieces).encode()).hex()


def _lire_etiquette(mk: dict, domaine: str, chemin: str) -> bytes:
    brut = mk.get(f"{domaine}_tag")
    if not isinstance(brut, str):
        raise ConventionPerimee(
            f"ARRÊT : `{domaine}_tag` absent de {chemin}. Une étiquette de domaine se LIT, "
            "elle ne se recopie pas à la main — et un fichier qui n'en porte aucune est "
            "ANTÉRIEUR à la séparation de domaine (red team F03). Ces artefacts sont "
            "périmés : refaire le lot publié "
            "(`python3 -B -m veilleur.outils.faire_lot_public --contracts <arbre à jour>`) "
            "AVANT de calculer la moindre feuille.")
    m = _ETIQUETTE.search(brut)
    if not m:
        raise ConventionPerimee(
            f"ARRÊT : `{domaine}_tag` ne porte pas la forme `keccak256(\"…\") = 0x<64>` "
            f"({brut!r}). Sans préimage citée, l'empreinte n'est pas vérifiable.")
    preimage, hexa = m.group(1), m.group(2)
    calcule = keccak256(preimage.encode())
    annonce = bytes.fromhex(hexa[2:])
    if calcule != annonce:
        raise ConventionPerimee(
            f"ARRÊT : `{domaine}_tag` — keccak256({preimage!r}) vaut 0x{calcule.hex()}, le "
            f"fichier annonce {hexa}. Deux autorités qui se contredisent : on s'arrête.")
    return annonce


def _types(champs: list, chemin: str) -> tuple:
    out = []
    for ch in champs:
        if not isinstance(ch, str) or not ch.strip():
            raise ConventionPerimee(f"ARRÊT : champ déclaré illisible dans {chemin} : {ch!r}")
        out.append(ch.split()[0])
    return tuple(out)


def charger(racine, exiger=DOMAINES_PAIEMENT) -> Convention:
    """Lit, vérifie et rend la convention de l'arbre d'artefacts `racine`.

    `exiger` : les domaines dont l'absence est un ARRÊT. Le contrôle anti-collision, lui,
    porte sur TOUS les domaines déclarés dans le fichier — y compris `season`, qui appartient
    à l'indexeur : le veilleur surveille le système, pas seulement sa propre moitié.
    """
    art = _artefacts.resoudre(racine)
    chemin = art.constants_path
    with open(chemin, encoding="utf-8") as fh:
        mk = (json.load(fh) or {}).get("merkle")
    if not isinstance(mk, dict) or not mk:
        raise ConventionPerimee(
            f"ARRÊT : pas de section `merkle` dans {chemin}. Un fichier muet n'est pas une "
            "convention, et lire zéro clé passerait « sans faute » (KE#111).")

    # ── (a) tous les domaines DÉCLARÉS, étiquette en PREMIER champ ───────────────────────
    # ORDRE : les gardes structurelles (a) et (b) passent AVANT la comparaison mot pour mot
    # (c). Dans l'autre sens, toute mutation d'une liste de champs serait interceptée par (c)
    # et les deux premières ne pourraient plus rougir sur aucune entrée : elles deviendraient
    # du code mort qu'on déclarerait porteur (KE#69 / KE#90).
    domaines = sorted(_SUFFIXE.sub("", k) for k in mk if _SUFFIXE.search(k))
    manquants = [d for d in exiger if d not in domaines]
    if manquants:
        raise ConventionPerimee(
            f"ARRÊT : domaines exigés absents de {chemin} : {manquants}. Les artefacts sont "
            "ANTÉRIEURS à la séparation de domaine — refaire le lot publié "
            "(`python3 -B -m veilleur.outils.faire_lot_public`) avant toute lecture.")
    if len(domaines) < 2:
        raise ConventionPerimee(
            f"ARRÊT : {len(domaines)} domaine(s) déclaré(s) dans {chemin}. Avec moins de deux, "
            "le contrôle de séparation n'a rien à séparer et passerait à vide (KE#111).")

    tags, champs, n = {}, {}, 0
    for dom in domaines:
        liste = mk.get(f"{dom}_fields")
        if not isinstance(liste, list) or not liste:
            raise ConventionPerimee(f"ARRÊT : `{dom}_fields` vide dans {chemin}.")
        tag = _lire_etiquette(mk, dom, chemin)
        tete = liste[0].split()
        attendu = "TAG_" + dom.upper()
        if tete[0] != "bytes32" or len(tete) < 2 or tete[1] != attendu:
            raise ConventionPerimee(
                f"ARRÊT : `{dom}_fields` ne commence PAS par « bytes32 {attendu} » "
                f"(lu : {liste[0]!r}). Sans étiquette en premier mot, la préimage de ce "
                "domaine est celle d'un autre : c'est la collision F03, pas une variante.")
        tags[dom], champs[dom] = tag, liste
        n += 1
    assert n == len(domaines), f"cardinal domaines : {n}"                        # KE#111

    # ── (b) AUCUN domaine n'ÉGALE ni ne PRÉFIXE un domaine de PAIEMENT ───────────────────
    # La signature épingle le PREMIER mot par sa VALEUR (c'est une constante) et les suivants
    # par leur TYPE. Comparer les listes telles qu'écrites laisserait passer deux domaines
    # identiques aux NOMS près — et les noms n'entrent pas dans `abi.encode`.
    def sig(d):
        return ("bytes32:" + tags[d].hex(),) + _types(champs[d], chemin)[1:]

    paires = 0
    for a in domaines:
        for b in DOMAINES_PAIEMENT:
            if a == b or b not in domaines:
                continue
            sa, sb = sig(a), sig(b)
            court, long_ = (sa, sb) if len(sa) <= len(sb) else (sb, sa)
            if long_[:len(court)] == court:
                raise ConventionPerimee(
                    f"ARRÊT : la signature de préimage du domaine « {a} » {sa} est ÉGALE ou "
                    f"PRÉFIXE de celle du domaine de PAIEMENT « {b} » {sb}. Une feuille de "
                    "l'un serait une feuille valide de l'autre : c'est exactement la "
                    "collision que la séparation de domaine doit rendre impossible.")
            paires += 1
    if paires == 0:
        raise ConventionPerimee(
            "ARRÊT : aucune paire croisée examinée — le contrôle de séparation serait passé "
            "à vide (KE#111).")

    # ── (c) et c'est bien, MOT POUR MOT, la convention pour laquelle ce module est écrit ──
    n = 0
    for k, attendu in CONVENTION_ATTENDUE.items():
        if mk.get(k) != attendu:
            raise ConventionPerimee(
                f"ARRÊT : la convention merkle « {k} » a changé dans {chemin} "
                f"({mk.get(k)!r} != {attendu!r}). Ce veilleur implémente l'ancienne : il ne "
                "doit calculer AUCUNE feuille tant qu'il n'a pas été relu. Ce n'est pas une "
                "divergence de racine de l'exploitant, c'est une obsolescence de module.")
        n += 1
    assert n == len(CONVENTION_ATTENDUE), f"cardinal convention : {n}"           # KE#111

    return Convention(chemin, racine, mk, tags, champs,
                      {d: _types(champs[d], chemin) for d in domaines}, tuple(domaines))


_DEFAUT = None


def defaut() -> Convention:
    """La convention de l'arbre d'artefacts que LE PAQUET résout par défaut (lot embarqué
    chez un tiers, `contracts/` voisin sinon). Mémorisée : un seul contrôle par processus."""
    global _DEFAUT
    if _DEFAUT is None:
        _DEFAUT = charger(_artefacts.racine_par_defaut())
    return _DEFAUT
