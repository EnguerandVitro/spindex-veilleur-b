"""Conformité de la convention merkle de `b` à sa SOURCE — pas à sa propre copie (KE#130 / KE#137 / KE#148).

Pourquoi ce fichier existe
--------------------------
Le 2026-09-24 la famille `backend/veilleur` est passée à la séparation de domaine (lot sécurité C-4 :
étiquette `TAG_CLAIM` / `TAG_DRAW` en PREMIER mot de chaque préimage). La copie de `b` est restée
quatre jours sur l'ancienne convention, et RIEN ne pouvait le dire : `sceau.py` compare la copie au
`FIGE.json` qu'elle transporte elle-même, donc une copie périmée ET son scellé périmé s'accordent
parfaitement. `b` calculait d'autres feuilles que `a` ne calculera après sa livraison, et que le
contrat redéployé n'acceptera jamais : il ne corroborait rien.

Ce module ferme ce trou par trois contrôles dont la référence n'est JAMAIS la copie :

1. ``vérifier`` (au démarrage de CHAQUE job, et au banc) — la COPIE exécutée recalcule des feuilles
   dorées ET doit tomber dessus au bit près. Les feuilles dorées sont dans
   ``config/vecteurs-convention.json`` et ne viennent pas de Python : elles sont calculées par
   ``cast`` (Foundry, implémentation Rust indépendante de keccak et d'`abi.encode`), depuis les
   préimages d'étiquette LUES DANS LE CONTRAT (``contracts/src/SpindexRewards.sol``). Chaque vecteur
   porte aussi la feuille SANS étiquette : si la copie retombe sur celle-là, c'est la collision F03,
   nommée comme telle. Couverture (KE#111) : chaque domaine de paiement doit avoir été exercé.
2. ``contrôler-générateur`` (machine du keeper, au banc) — KE#148 : le fichier de vecteurs est un
   fichier GÉNÉRÉ, donc il se vérifie contre SON GÉNÉRATEUR, relancé aujourd'hui sur la source
   d'aujourd'hui. Si le contrat ou la convention scellée changent d'étiquette, de champs ou d'ordre,
   la régénération diffère du fichier et ce contrôle ROUGIT — c'est lui qui voit une nouvelle
   divergence de convention, même si la copie n'a pas bougé.
3. ``recouper-source`` (machine du keeper, au banc) — la convention de la copie, celle de la
   famille scellée ``backend/veilleur`` et celle de l'autorité amont ``contracts/rewards`` doivent
   être IDENTIQUES, le scellé de la famille valide, et le ``FIGE.json`` porté par la copie doit être
   CELUI de la famille aujourd'hui (fraîcheur, KE#137). Les deux paquets calculent leur empreinte de
   convention chacun dans SON sous-processus, et le chemin du module réellement chargé est vérifié
   (KE#106 : un import qui résout le mauvais arbre rend tout contrôle faussement vert).

Les contrôles 2 et 3 exigent l'arbre du projet et ``cast`` : ils ne tournent pas sur le runner, qui
n'a ni l'un ni l'autre. Le contrôle 1 n'exige rien d'autre que la copie : il tourne partout.

    python3 -B outils/conformite.py vérifier
    python3 -B outils/conformite.py générer              --projet ~/stockslot
    python3 -B outils/conformite.py contrôler-générateur --projet ~/stockslot
    python3 -B outils/conformite.py recouper-source      --projet ~/stockslot

Codes de sortie : 0 conforme · 2 ARRÊT (non conforme, ou contrôle impossible — jamais « à peu près »).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAQUET = os.path.join(ICI, "veilleur")
VECTEURS = os.path.join(ICI, "config", "vecteurs-convention.json")
FORMAT = 1
DOMAINES_PAIEMENT = ("claim", "draw")

# Chemins DANS le projet (relatifs à sa racine). Ce sont les autorités, pas des copies.
CONTRAT_SRC = "contracts/src/SpindexRewards.sol"
CONSTANTES_AMONT = "contracts/rewards/rewards_constants.json"
FAMILLE = "backend/veilleur"

# Entrées des vecteurs : des VALEURS, pas une convention (aucune étiquette, aucun ordre de champs,
# aucun type ici — tout cela est LU à la source). Le premier tuple de `claim` est l'ancre chiffrée de
# la red team (lot C-4 / rapport veilleur §12.4) ; les autres visent les bords de l'encodage :
# zéros, adresse aux 160 bits pleins, uint256 maximal.
_MAX = 2 ** 256 - 1
_A1 = "0x00000000000000000000000000000000000000a1"
_AF = "0xffffffffffffffffffffffffffffffffffffffff"
_A0 = "0x0000000000000000000000000000000000000000"
_AM = "0x8ba1f109551bd432803012645ac136ddd64dba72"
ENTREES = {
    "claim": [
        [_A1, 7, 12_000_000, 3_000_000],
        [_A0, 0, 0, 0],
        [_AF, _MAX, _MAX, _MAX],
        [_AM, 1, 1, 0],
    ],
    "draw": [
        [_A1, 7, 0, 0, 12_000_000],
        [_A0, 0, 0, 0, 0],
        [_AF, _MAX, _MAX, _MAX - 1, _MAX],
        [_AM, 3, 41, 1_000, 2_500],
    ],
}
# Ancres PUBLIÉES par d'autres ateliers, avec d'autres implémentations (indexeur : autre keccak,
# autre encodeur). Le générateur REFUSE d'écrire si cast ne les retrouve pas : trois implémentations
# doivent s'accorder avant qu'un vecteur devienne une référence.
ANCRES = {("claim", 0): {"avec_etiquette_prefixe": "0xfba68a85", "sans_etiquette_prefixe": "0x2d935f84",
                         "source": "LOT_SECURITE_2026-09 §C-4 / backend/rapports/veilleur.md §12.4"}}


class NonConforme(RuntimeError):
    """ARRÊT bruyant. Une convention non prouvée ne calcule aucune feuille."""


def _sha256_fichier(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def section_merkle(chemin):
    with open(chemin, encoding="utf-8") as fh:
        mk = (json.load(fh) or {}).get("merkle")
    if not isinstance(mk, dict) or not mk:
        raise NonConforme(f"ARRÊT : pas de section `merkle` dans {chemin} (KE#111).")
    return mk


def empreinte_section(mk):
    """sha256 de la section `merkle` sérialisée canoniquement : une seule autorité, pas une prose."""
    return hashlib.sha256(json.dumps(mk, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------ 1. vérifier

def _charger_merkle_de_la_copie():
    """Importe `veilleur.merkle` DEPUIS LA COPIE et prouve que c'est bien elle qui a été chargée."""
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    import veilleur.merkle as merkle
    charge = os.path.realpath(merkle.__file__)
    attendu = os.path.realpath(os.path.join(PAQUET, "merkle.py"))
    if charge != attendu:                                                              # KE#106
        raise NonConforme(f"ARRÊT : `veilleur.merkle` chargé depuis {charge}, attendu {attendu}. "
                          f"Le contrôle mesurerait un autre arbre que celui qui tourne.")
    return merkle


def verifier(chemin_vecteurs=VECTEURS):
    if not os.path.exists(chemin_vecteurs):
        raise NonConforme(f"ARRÊT : {chemin_vecteurs} absent. Sans vecteurs dorés, rien ne relie la "
                          f"copie à la convention du contrat (KE#130).")
    with open(chemin_vecteurs, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("format") != FORMAT:
        raise NonConforme(f"ARRÊT : vecteurs au format {doc.get('format')}, attendu {FORMAT}.")

    # (a) les vecteurs ont été générés pour la convention que la copie embarque — sinon on
    #     comparerait deux mondes et un accord ne prouverait rien.
    mk = section_merkle(os.path.join(PAQUET, "public", "rewards_constants.json"))
    lue, annoncee = empreinte_section(mk), doc.get("convention_sha256")
    if lue != annoncee:
        raise NonConforme(
            f"ARRÊT : la convention embarquée par la copie ({lue[:16]}…) n'est PAS celle pour laquelle "
            f"les vecteurs ont été générés ({str(annoncee)[:16]}…). La copie et la référence ont "
            f"divergé : resynchroniser la copie OU régénérer les vecteurs depuis la source, jamais "
            f"l'un sans l'autre.")

    # (b) la COPIE recalcule chaque feuille dorée, au bit près.
    merkle = _charger_merkle_de_la_copie()
    fonctions = {"claim": merkle.leaf_week, "draw": merkle.leaf_draw}
    compte, ecarts = {}, []
    for dom in DOMAINES_PAIEMENT:
        for i, v in enumerate((doc.get("vecteurs") or {}).get(dom) or []):
            entree = [e if e.startswith("0x") else int(e) for e in v["entree"]]
            calc = "0x" + fonctions[dom](*entree).hex()
            if calc == v["feuille_sans_etiquette"]:
                ecarts.append(f"{dom}[{i}] : la copie calcule la feuille SANS étiquette ({calc[:18]}…) — "
                              f"c'est la collision F03 (lot C-4), la séparation de domaine est absente")
            elif calc != v["feuille"]:
                ecarts.append(f"{dom}[{i}] : copie {calc}, référence {v['feuille']}")
            compte[dom] = compte.get(dom, 0) + 1
    if ecarts:
        raise NonConforme("ARRÊT : la copie ne calcule pas les feuilles du contrat.\n  "
                          + "\n  ".join(ecarts))
    # (c) COUVERTURE (KE#111 / KE#141) : le cardinal APPARIÉ par domaine, jamais le déclaré.
    vides = [d for d in DOMAINES_PAIEMENT if not compte.get(d)]
    if vides:
        raise NonConforme(f"ARRÊT : aucun vecteur exercé pour {vides} — le contrôle passerait à vide.")
    return {"convention_sha256": lue, "vecteurs_par_domaine": compte,
            "merkle_charge_depuis": os.path.realpath(merkle.__file__)}


# ------------------------------------------------------------------------------------ 2. générer

def _cast():
    c = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")
    if not os.path.exists(c):
        raise NonConforme("ARRÊT : `cast` (Foundry) introuvable. Les vecteurs doivent être calculés par "
                          "une implémentation INDÉPENDANTE du veilleur ; sans elle, on ne génère rien.")
    return c


def _run_cast(cast, *args):
    r = subprocess.run([cast, *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise NonConforme(f"ARRÊT : cast {args[0]} a échoué : {r.stderr.strip()[:300]}")
    return r.stdout.strip().lower()


def _etiquettes_du_contrat(chemin_sol):
    """Préimages lues DANS LE CONTRAT : `bytes32 public constant TAG_X = keccak256("…");`."""
    with open(chemin_sol, encoding="utf-8") as fh:
        src = fh.read()
    trouve = dict(re.findall(r'bytes32\s+public\s+constant\s+TAG_([A-Z]+)\s*=\s*keccak256\("([^"]+)"\)', src))
    manquants = [d for d in DOMAINES_PAIEMENT if d.upper() not in trouve]
    if manquants:
        raise NonConforme(f"ARRÊT : {chemin_sol} ne déclare pas TAG_ pour {manquants}. Le contrat est "
                          f"ANTÉRIEUR à la séparation de domaine, ou sa forme a changé : rien n'est deviné.")
    return {d: trouve[d.upper()] for d in DOMAINES_PAIEMENT}


def generer(projet):
    """Construit le document de vecteurs depuis la SOURCE. Pur : aucune date, aucune version d'outil
    — deux générations sur la même source rendent le même octet (sinon `contrôler-générateur` rougirait
    pour du bruit, et on finirait par rafraîchir le fichier machinalement : KE#147)."""
    cast = _cast()
    sol = os.path.join(projet, CONTRAT_SRC)
    cst = os.path.join(projet, CONSTANTES_AMONT)
    mk = section_merkle(cst)
    preimages = _etiquettes_du_contrat(sol)

    vecteurs = {}
    for dom in DOMAINES_PAIEMENT:
        tag = _run_cast(cast, "keccak", preimages[dom])
        # recoupe : l'étiquette que la convention scellée ANNONCE doit être celle que cast calcule
        # depuis la préimage du CONTRAT (deux autorités, une implémentation tierce).
        annonce = re.search(r"=\s*(0x[0-9a-fA-F]{64})", str(mk.get(f"{dom}_tag") or ""))
        if not annonce or annonce.group(1).lower() != tag:
            raise NonConforme(f"ARRÊT : `{dom}_tag` de {cst} ne correspond pas à keccak256 de la préimage "
                              f"du contrat ({preimages[dom]!r} -> {tag}).")
        champs = mk.get(f"{dom}_fields") or []
        types = [c.split()[0] for c in champs]
        if not types or types[0] != "bytes32" or champs[0].split()[1:2] != [f"TAG_{dom.upper()}"]:
            raise NonConforme(f"ARRÊT : `{dom}_fields` de {cst} ne commence pas par l'étiquette : {champs[:1]}")
        sig_avec = "f(" + ",".join(types) + ")"
        sig_sans = "f(" + ",".join(types[1:]) + ")"
        lignes = []
        for entree in ENTREES[dom]:
            if len(entree) != len(types) - 1:
                raise NonConforme(f"ARRÊT : {dom} déclare {len(types) - 1} champ(s) après l'étiquette, "
                                  f"le vecteur en porte {len(entree)}. La convention a changé : "
                                  f"réviser ENTREES, pas le contrôle.")
            args = [str(e) for e in entree]
            enc_avec = _run_cast(cast, "abi-encode", sig_avec, tag, *args)
            enc_sans = _run_cast(cast, "abi-encode", sig_sans, *args)
            f_avec = _run_cast(cast, "keccak", _run_cast(cast, "keccak", enc_avec))
            f_sans = _run_cast(cast, "keccak", _run_cast(cast, "keccak", enc_sans))
            if f_avec == f_sans:
                raise NonConforme(f"ARRÊT : {dom} — feuille identique avec et sans étiquette : impossible.")
            lignes.append({"entree": [e if isinstance(e, str) else str(e) for e in entree],
                           "feuille": f_avec, "feuille_sans_etiquette": f_sans})
        vecteurs[dom] = lignes

    for (dom, i), a in ANCRES.items():
        v = vecteurs[dom][i]
        if not (v["feuille"].startswith(a["avec_etiquette_prefixe"])
                and v["feuille_sans_etiquette"].startswith(a["sans_etiquette_prefixe"])):
            raise NonConforme(f"ARRÊT : cast ne retrouve pas l'ancre publiée {dom}[{i}] ({a['source']}) : "
                              f"{v['feuille'][:10]} / {v['feuille_sans_etiquette'][:10]}.")

    return {
        "format": FORMAT,
        "genere_par": "outils/conformite.py générer — NE PAS ÉDITER : se vérifie contre son générateur "
                      "(`contrôler-générateur`, KE#148)",
        "calcule_par": "cast (Foundry) : keccak et abi-encode, implémentation indépendante du veilleur",
        "sources": {CONTRAT_SRC: _sha256_fichier(sol), CONSTANTES_AMONT: _sha256_fichier(cst)},
        "etiquettes_preimages_du_contrat": preimages,
        "convention_sha256": empreinte_section(mk),
        "ancres_publiees": {f"{d}[{i}]": a for (d, i), a in ANCRES.items()},
        "vecteurs": vecteurs,
    }


def _serialiser(doc):
    return json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def ecrire(doc, chemin=VECTEURS):
    tmp = chemin + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(_serialiser(doc))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, chemin)                                                              # KE#112


def controler_generateur(projet, chemin=VECTEURS):
    if not os.path.exists(chemin):
        raise NonConforme(f"ARRÊT : {chemin} absent — rien à confronter à son générateur.")
    with open(chemin, encoding="utf-8") as fh:
        present = fh.read()
    regenere = _serialiser(generer(projet))
    if present != regenere:
        a, b = json.loads(present), json.loads(regenere)
        diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        raise NonConforme(
            f"ARRÊT : {os.path.relpath(chemin, ICI)} ne correspond plus à ce que son générateur produit "
            f"AUJOURD'HUI depuis la source (clés divergentes : {diff}). La convention du contrat ou de la "
            f"famille a bougé depuis la génération : la copie de b est peut-être à nouveau périmée. "
            f"Resynchroniser, puis régénérer — jamais régénérer seul (KE#147/#148).")
    return {"octets": len(present), "sources": json.loads(regenere)["sources"]}


# ------------------------------------------------------------------------------ 3. recouper-source

_SONDE = (
    "import os,sys,json\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "os.environ.pop('SPINDEX_VEILLEUR_ARTEFACTS', None)\n"
    "from veilleur import convention as c\n"
    "cv = c.defaut()\n"
    "print(json.dumps({'fichier': os.path.realpath(c.__file__), 'empreinte': cv.empreinte(),"
    " 'chemin': os.path.realpath(cv.chemin)}))\n"
)


def _empreinte_convention(parent, paquet_attendu):
    env = {k: v for k, v in os.environ.items() if k != "SPINDEX_VEILLEUR_ARTEFACTS"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run([sys.executable, "-B", "-c", _SONDE, parent], capture_output=True, text=True,
                       cwd="/", env=env, timeout=120)
    if r.returncode != 0:
        raise NonConforme(f"ARRÊT : la convention de {paquet_attendu} ne se charge pas :\n{r.stderr.strip()[-600:]}")
    d = json.loads(r.stdout.strip().splitlines()[-1])
    if not d["fichier"].startswith(os.path.realpath(paquet_attendu) + os.sep):                # KE#106
        raise NonConforme(f"ARRÊT : sonde chargée depuis {d['fichier']}, attendu sous {paquet_attendu}.")
    return d


def recouper_source(projet):
    projet = os.path.realpath(projet)
    famille = os.path.join(projet, FAMILLE)

    # (a) le scellé de la famille est VALIDE aujourd'hui (sinon la « source » est un arbre ouvert)
    frozen = os.path.join(projet, "contracts", "script", "frozen.py")
    r = subprocess.run([sys.executable, "-B", frozen, "check", FAMILLE], capture_output=True, text=True,
                       cwd=os.path.join(projet, "contracts"), timeout=300)
    if r.returncode != 0:
        raise NonConforme(f"ARRÊT : `frozen.py check {FAMILLE}` sort {r.returncode} : la source n'est pas "
                          f"scellée, elle ne peut servir de référence.\n{(r.stdout + r.stderr).strip()[-400:]}")

    # (b) FRAÎCHEUR (KE#137) : la copie porte le scellé de la famille D'AUJOURD'HUI, octet pour octet
    fige_copie = _sha256_fichier(os.path.join(PAQUET, "FIGE.json"))
    fige_famille = _sha256_fichier(os.path.join(famille, "FIGE.json"))
    if fige_copie != fige_famille:
        raise NonConforme(f"ARRÊT : la copie porte le FIGE.json {fige_copie[:16]}…, la famille est scellée "
                          f"en {fige_famille[:16]}… — la copie est PÉRIMÉE (resynchroniser).")

    # (c) trois textes de convention, un seul contenu : copie, famille scellée, autorité amont
    sections = {
        "copie b": os.path.join(PAQUET, "public", "rewards_constants.json"),
        f"{FAMILLE} (scellée)": os.path.join(famille, "public", "rewards_constants.json"),
        f"{CONSTANTES_AMONT} (autorité)": os.path.join(projet, CONSTANTES_AMONT),
    }
    emp = {k: empreinte_section(section_merkle(p)) for k, p in sections.items()}
    if len(set(emp.values())) != 1:
        raise NonConforme("ARRÊT : les conventions divergent :\n  "
                          + "\n  ".join(f"{k} : {v}" for k, v in emp.items()))
    # le contrat embarqué est celui de la source (un lot plus vieux que le contrat = KE#137)
    if _sha256_fichier(os.path.join(PAQUET, "public", "SpindexRewards.sol")) != \
            _sha256_fichier(os.path.join(projet, CONTRAT_SRC)):
        raise NonConforme(f"ARRÊT : le SpindexRewards.sol embarqué par la copie n'est pas {CONTRAT_SRC}.")

    # (d) chaque PAQUET calcule l'empreinte de SA convention, dans son propre processus
    copie = _empreinte_convention(ICI, PAQUET)
    source = _empreinte_convention(os.path.dirname(famille), famille)
    if copie["empreinte"] != source["empreinte"]:
        raise NonConforme(f"ARRÊT : empreinte de convention — copie {copie['empreinte']}, "
                          f"famille {source['empreinte']}. Les deux veilleurs ne calculent pas les mêmes feuilles.")
    return {"convention_sha256": emp[f"{CONSTANTES_AMONT} (autorité)"],
            "empreinte_convention": copie["empreinte"], "fige": fige_famille,
            "copie_chargee": copie["fichier"], "famille_chargee": source["fichier"]}


# ------------------------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("vérifier", "verifier", "générer", "generer",
                                       "contrôler-générateur", "controler-generateur", "recouper-source"))
    ap.add_argument("--projet", help="racine du projet (machine du keeper) — requis hors `vérifier`")
    ap.add_argument("--vecteurs", default=VECTEURS)
    a = ap.parse_args(argv)
    action = a.action.replace("é", "e").replace("ô", "o")
    try:
        if action == "verifier":
            rep = verifier(a.vecteurs)
            print(f"CONVENTION CONFORME : la copie retrouve les feuilles du contrat au bit près "
                  f"({', '.join(f'{d} {n}' for d, n in rep['vecteurs_par_domaine'].items())} vecteur(s)), "
                  f"convention {rep['convention_sha256'][:16]}…")
            return 0
        if not a.projet:
            print(f"ARRÊT : `{a.action}` exige --projet (arbre source et cast).", file=sys.stderr)
            return 2
        if action == "generer":
            doc = generer(a.projet)
            ecrire(doc, a.vecteurs)
            print(f"vecteurs écrits : {a.vecteurs} "
                  f"({', '.join(f'{d} {len(v)}' for d, v in doc['vecteurs'].items())}), "
                  f"convention {doc['convention_sha256'][:16]}…")
            return 0
        if action == "controler-generateur":
            rep = controler_generateur(a.projet, a.vecteurs)
            print(f"VECTEURS = GÉNÉRATEUR : {rep['octets']} octets identiques à la régénération depuis la source")
            return 0
        rep = recouper_source(a.projet)
        print(f"SOURCE RECOUPÉE : copie, famille scellée et autorité amont portent la même convention "
              f"({rep['convention_sha256'][:16]}…, empreinte paquet {rep['empreinte_convention'][:16]}…), "
              f"FIGE {rep['fige'][:16]}…")
        return 0
    except NonConforme as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
