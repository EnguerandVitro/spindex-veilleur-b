"""Le sceau de la COPIE : fabriquer `SCEAU.json`, et REFUSER de démarrer si la copie a bougé.

Pourquoi ce fichier existe
--------------------------
`veilleur-b/veilleur/` est une **copie** de la famille scellée `backend/veilleur/`. Une copie n'est pas
une preuve : sans contrôle, le second veilleur pourrait tourner sur un code différent de celui que le
premier exécute, et deux instances qui ne font pas le même travail ne se contrôlent pas — elles se
donnent l'illusion de se contrôler.

Trois ancrages, et ils ne viennent PAS du même endroit (KE#130 : la borne vient de la SOURCE) :

1. **`SCEAU.json`** — mon manifeste : l'empreinte sha256 de chaque fichier copié. Il attrape une
   modification locale de la copie. À lui seul il ne prouve rien d'autre : je l'ai fabriqué, donc
   quelqu'un qui modifie la copie peut le refabriquer.
2. **`veilleur/FIGE.json`** — le scellé produit par la famille elle-même, copié tel quel. Chaque
   fichier copié y est confronté à l'empreinte que la famille a scellée. C'est l'ancrage qui compte :
   la référence n'est pas de moi.
3. **`empreinte_sources()`** — la fonction du paquet scellé (`veilleur/battement.py`), recalculée sur
   la copie et comparée à la valeur épinglée. Cette même valeur est **publiée à chaque passe par
   l'instance `a`** dans son `health.json` : la surveillance peut donc comparer les deux instances
   sans rien demander à personne. C'est le seul des trois qui soit vérifiable de l'extérieur, en
   service, par un tiers.

Un intrus (fichier présent dans `veilleur/` mais absent du manifeste) est un ARRÊT, pas un
avertissement : « un lot qui contient autre chose que ce qu'il annonce n'est pas un lot »
(`veilleur/artefacts.py`). Il le faut d'autant plus ici qu'un `.py` de plus à la racine du paquet
**change `empreinte_sources()`** : le laisser passer déplacerait silencieusement l'ancrage 3.

Assertions de COUVERTURE (KE#111) : un manifeste vide, ou un croisement avec le scellé qui ne porte
sur aucun fichier, passerait « sans faute » en n'ayant rien vérifié. Les deux cardinaux sont donc
contrôlés, et **tout `*.py` de la racine du paquet** (c'est-à-dire tout ce qui entre dans
`empreinte_sources()`) doit avoir été croisé avec le scellé.

    python3 -B outils/sceau.py fabriquer   # sur la machine qui détient la famille scellée
    python3 -B outils/sceau.py vérifier    # au démarrage de CHAQUE job
"""
import hashlib
import json
import os
import sys

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAQUET = os.path.join(ICI, "veilleur")
SCEAU = os.path.join(ICI, "SCEAU.json")
FORMAT = 1

# Préfixe des chemins tels que le scellé de la famille les nomme.
PREFIXE_SCELLE = "backend/veilleur/"


class SceauError(RuntimeError):
    """ARRÊT bruyant. Jamais de dégradation : une copie non prouvée ne surveille rien."""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def fichiers_copies():
    """Tous les fichiers sous `veilleur/`, chemins relatifs à la racine du dépôt, triés."""
    out = []
    for racine, _dirs, noms in os.walk(PAQUET):
        for n in sorted(noms):
            if n == "__pycache__" or racine.endswith("__pycache__"):
                continue
            p = os.path.join(racine, n)
            out.append(os.path.relpath(p, ICI))
    return sorted(out)


def empreinte_sources_de_la_copie():
    """`empreinte_sources()` du paquet scellé, appliquée à LA COPIE.

    Importée depuis la copie elle-même : c'est le code qui tournera, donc la même fonction que celle
    qui écrira l'empreinte dans les battements et le `health.json` de l'instance `b`.
    """
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    from veilleur.battement import empreinte_sources
    return empreinte_sources(PAQUET)


def lire_scelle():
    """Le scellé de la famille, tel qu'il a été copié. Illisible = ARRÊT."""
    p = os.path.join(PAQUET, "FIGE.json")
    if not os.path.exists(p):
        raise SceauError(
            f"ARRÊT : {p} absent. Sans le scellé de la famille, la copie n'a plus qu'un manifeste que "
            f"j'ai moi-même fabriqué — c'est-à-dire aucune référence extérieure (KE#130).")
    with open(p, encoding="utf-8") as fh:
        doc = json.load(fh)
    art = doc.get("artefacts") or {}
    if not art:
        raise SceauError(f"ARRÊT : {p} n'épingle AUCUN artefact — il ne scelle rien (KE#111).")
    return doc, art


# ------------------------------------------------------------------------------------- fabriquer

def fabriquer(source_release=None):
    doc_fige, art = lire_scelle()
    copies = fichiers_copies()
    if not copies:
        raise SceauError("ARRÊT : aucun fichier copié sous veilleur/ (KE#111).")
    empreintes = {rel: sha256(os.path.join(ICI, rel)) for rel in copies}

    livraison = {}
    p_liv = os.path.join(PAQUET, "LIVRAISON.json")
    if os.path.exists(p_liv):
        with open(p_liv, encoding="utf-8") as fh:
            d = json.load(fh)
        livraison = {"empreinte": d.get("empreinte"), "construite_le": d.get("construite_le"),
                     "manifeste_scelle_sha256": (d.get("manifestes_scelle") or {}).get("backend/veilleur/FIGE.json")}

    non_copies = sorted(k for k in art
                        if k.startswith(PREFIXE_SCELLE)
                        and os.path.join("veilleur", k[len(PREFIXE_SCELLE):]) not in copies)

    doc = {
        "format": FORMAT,
        "quoi": "empreintes de la COPIE du paquet scellé backend/veilleur, telle qu'elle est exécutée "
                "par le job GitHub Actions de l'instance b",
        "source": {
            "famille": doc_fige.get("famille"),
            "atelier": doc_fige.get("atelier"),
            "scelle_le": doc_fige.get("scelle_le"),
            "release": livraison.get("empreinte"),
            "release_construite_le": livraison.get("construite_le"),
            "fige_json_sha256": sha256(os.path.join(PAQUET, "FIGE.json")),
            "fige_json_sha256_declare_par_la_livraison": livraison.get("manifeste_scelle_sha256"),
        },
        "empreinte_sources_attendue": empreinte_sources_de_la_copie(),
        "ou_la_verifier": "la MÊME valeur est publiée à chaque passe par l'instance a dans son "
                          "health.json (champ « empreinte ») et dans chacun de ses battements. Deux "
                          "instances qui ne portent pas la même empreinte n'exécutent pas le même code.",
        "fichiers": empreintes,
        "non_copies_du_scelle": non_copies,
        "pourquoi_non_copies": "banc, unités systemd, mesures et outils de la famille : ils ne sont pas "
                               "exécutés par le job. Ils n'entrent pas non plus dans empreinte_sources(), "
                               "qui ne porte que sur les *.py de la RACINE du paquet.",
    }
    tmp = SCEAU + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, SCEAU)
    return doc


# -------------------------------------------------------------------------------------- vérifier

def verifier():
    """Rend un rapport. Lève `SceauError` au premier défaut : rien ne « dégrade »."""
    if not os.path.exists(SCEAU):
        raise SceauError(f"ARRÊT : {SCEAU} absent. La copie n'est pas scellée, donc rien ne dit qu'elle "
                         f"correspond à la famille. Le job ne lit pas la chaîne.")
    with open(SCEAU, encoding="utf-8") as fh:
        sc = json.load(fh)
    if sc.get("format") != FORMAT:
        raise SceauError(f"ARRÊT : SCEAU.json au format {sc.get('format')}, attendu {FORMAT}.")
    attendus = sc.get("fichiers") or {}
    if not attendus:
        raise SceauError("ARRÊT : SCEAU.json n'épingle AUCUN fichier — il ne gèle rien (KE#111).")

    # --- 1. chaque fichier épinglé est présent et inchangé
    bouges = []
    for rel, want in sorted(attendus.items()):
        p = os.path.join(ICI, rel)
        if not os.path.exists(p):
            bouges.append((rel, want, "ABSENT"))
        else:
            got = sha256(p)
            if got != want:
                bouges.append((rel, want, got))
    if bouges:
        lignes = "\n".join(f"  {r}\n    scellé {w}\n    lu     {g}" for r, w, g in bouges)
        raise SceauError(f"ARRÊT : {len(bouges)} fichier(s) de la copie ont bougé depuis le sceau.\n{lignes}")

    # --- 2. aucun intrus (un .py de plus à la racine DÉPLACERAIT empreinte_sources)
    presents = set(fichiers_copies())
    intrus = sorted(presents - set(attendus))
    if intrus:
        raise SceauError(
            f"ARRÊT : {len(intrus)} fichier(s) présents sous veilleur/ mais absents du sceau : "
            f"{intrus[:5]}. Une copie qui contient autre chose que ce qu'elle annonce n'est pas une copie.")

    # --- 3. croisement avec le scellé DE LA FAMILLE : la référence n'est pas de moi (KE#130)
    _doc_fige, art = lire_scelle()
    croises, ecarts = 0, []
    for rel, empreinte in sorted(attendus.items()):
        if not rel.startswith("veilleur/"):
            continue
        cle = PREFIXE_SCELLE + rel[len("veilleur/"):]
        if cle not in art:
            continue                       # FIGE.json / LIVRAISON.json ne se scellent pas eux-mêmes
        croises += 1
        if art[cle] != empreinte:
            ecarts.append((rel, art[cle], empreinte))
    if ecarts:
        lignes = "\n".join(f"  {r}\n    famille {a}\n    copie   {b}" for r, a, b in ecarts)
        raise SceauError(
            f"ARRÊT : {len(ecarts)} fichier(s) de la copie DIVERGENT du scellé de la famille.\n{lignes}\n"
            f"Le sceau local est d'accord avec la copie, la famille ne l'est pas : c'est la famille qui "
            f"a raison (KE#130).")

    # --- 4. COUVERTURE (KE#111) : tout ce qui entre dans empreinte_sources doit avoir été croisé
    racine_py = sorted(f for f in os.listdir(PAQUET) if f.endswith(".py"))
    if not racine_py:
        raise SceauError("ARRÊT : aucun *.py à la racine du paquet : empreinte_sources() n'aurait rien "
                         "à empreinter (KE#111).")
    non_croises = [f for f in racine_py if (PREFIXE_SCELLE + f) not in art]
    if non_croises:
        raise SceauError(
            f"ARRÊT : {len(non_croises)} source(s) exécutée(s) ne sont PAS dans le scellé de la famille : "
            f"{non_croises}. Elles entrent pourtant dans empreinte_sources() : le contrôle croisé "
            f"passerait à côté d'elles.")
    if croises < len(racine_py):
        raise SceauError(f"ARRÊT : {croises} fichier(s) croisés avec le scellé pour {len(racine_py)} "
                         f"source(s) exécutée(s) : couverture incohérente.")

    # --- 5. l'empreinte des sources EN SERVICE, celle que l'instance a publie
    attendue = sc.get("empreinte_sources_attendue")
    lue = empreinte_sources_de_la_copie()
    if not attendue:
        raise SceauError("ARRÊT : SCEAU.json ne porte pas d'empreinte_sources attendue : il n'y aurait "
                         "rien à comparer au health.json de l'instance a.")
    if lue != attendue:
        raise SceauError(
            f"ARRÊT : empreinte des sources en service {lue}, le sceau attend {attendue}. La copie "
            f"n'exécute pas le code scellé.")

    return {"fichiers_verifies": len(attendus), "croises_avec_le_scelle": croises,
            "sources_executees": len(racine_py), "empreinte_sources": lue,
            "release": (sc.get("source") or {}).get("release"),
            "scelle_le": (sc.get("source") or {}).get("scelle_le")}


def main(argv):
    if len(argv) < 2 or argv[1] not in ("fabriquer", "vérifier", "verifier"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        if argv[1] == "fabriquer":
            doc = fabriquer()
            print(f"SCEAU.json écrit : {len(doc['fichiers'])} fichier(s), empreinte des sources "
                  f"{doc['empreinte_sources_attendue']}")
            print(f"  famille  : {doc['source']['famille']} scellée le {doc['source']['scelle_le']}")
            print(f"  release  : {doc['source']['release']}")
            return 0
        rep = verifier()
        print(f"COPIE PROUVÉE : {rep['fichiers_verifies']} fichier(s) inchangés, "
              f"{rep['croises_avec_le_scelle']} croisés avec le scellé de la famille, "
              f"{rep['sources_executees']} source(s) exécutée(s).")
        print(f"  empreinte des sources : {rep['empreinte_sources']}")
        print(f"  (l'instance a publie la MÊME valeur dans son health.json)")
        return 0
    except SceauError as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
