"""Le LOT publié par l'instance `b` : les fichiers que la surveillance lit, plus une signature.

Le problème que ce fichier résout
---------------------------------
L'instance `a` écrit son état sur le disque de la machine que la surveillance lit : personne d'autre
n'a pu l'écrire. L'instance `b` publie le sien **à travers GitHub**, c'est-à-dire à travers un tiers
et un compte. Recopié tel quel, `battement-passe.json` ne prouverait rien : n'importe qui ayant le
droit d'écrire dans le dépôt pourrait fabriquer un battement vert pour un veilleur mort.

Le lot porte donc un **manifeste** (l'empreinte sha256 de chaque fichier publié, plus le contexte de
l'exécution) et **une signature Ed25519** de ce manifeste, par la clé d'attestation de `b` — la même
clé qui signe ses feux verts, et qui ne vit que dans le secret GitHub. Ce qu'un tiers peut alors
dire : « ces octets-là viennent bien du détenteur de la clé `b` ». Ce qu'il ne peut toujours pas
dire : voir la section « Ce que ce lot ne prouve pas », plus bas et dans le README.

**Séparation de domaine.** Le domaine signé ici (`spindex-veilleur-b-lot/1`) n'est pas celui des
verdicts (`spindex-veilleur-verdict/1`). Sans cela, la signature d'un lot pourrait un jour être
présentée comme un feu vert : c'est exactement ce contre quoi `verdict.verify_envelope` vérifie déjà
le domaine.

**Le lot est publié même quand le jugement est ROUGE**, et il porte le jugement. Un veilleur qui se
tait quand il trouve quelque chose serait pire qu'un veilleur absent.

Ce que ce lot ne prouve pas
----------------------------
- Que le job a bien tourné à l'heure : la signature n'horodate rien d'opposable, l'horloge est celle
  du runner. Le `ts` du battement vient de la même machine.
- Que personne n'a effacé un lot : une signature prouve ce qui est là, jamais ce qui manque. C'est la
  surveillance, en voyant le silence, qui doit le dire (`service_muet`).
- Que la clé n'a pas été utilisée ailleurs : GitHub voit le secret (README, « Ce que ce montage ne
  protège pas »).

    python3 -B outils/publier.py --etat <dossier> --lot <dossier> --jugement lot/JUGEMENT.json
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTILS = os.path.dirname(os.path.abspath(__file__))
for _p in (ICI, OUTILS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SCHEMA = "spindex-veilleur-b-lot/1"
DOMAINE = b"spindex-veilleur-b-lot/1\n"
MANIFESTE = "MANIFESTE.json"
SIGNATURE = "SIGNATURE.json"

# Ce qui est publié, et rien d'autre. Le cache des journaux n'y est PAS : c'est de l'état de travail,
# reconstructible depuis la chaîne, et il n'a aucune valeur de preuve pour un tiers.
A_PUBLIER = ("health.json", "amorcage.json", "durees.json",
             "battement-passe.json", "battement-differentiel-quotidien.json",
             "battement-differentiel-complet.json",
             "derniere-passe.json", "derniere-differentiel-quotidien.json",
             "derniere-differentiel-complet.json")
DOSSIERS_A_PUBLIER = ("verdicts",)


class PublierError(RuntimeError):
    pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def _contexte_execution():
    """Ce que l'exécutant dit de lui-même. C'est une DÉCLARATION, pas une preuve : GitHub pose ces
    variables, et quiconque exécute le script peut les poser aussi. Elles servent à retrouver le job
    dans les journaux du fournisseur, pas à authentifier quoi que ce soit."""
    e = os.environ
    depot = e.get("GITHUB_REPOSITORY")
    run = e.get("GITHUB_RUN_ID")
    return {
        "declare_par": "variables d'environnement du runner — DÉCLARATION, pas preuve",
        "fournisseur": "github-actions" if run else (e.get("SPINDEX_B_FOURNISSEUR") or "local"),
        "depot": depot,
        "run_id": run,
        "run_number": e.get("GITHUB_RUN_NUMBER"),
        "tentative": e.get("GITHUB_RUN_ATTEMPT"),
        "declencheur": e.get("GITHUB_EVENT_NAME"),
        "commit": e.get("GITHUB_SHA"),
        "url": (f"{e.get('GITHUB_SERVER_URL')}/{depot}/actions/runs/{run}"
                if depot and run and e.get("GITHUB_SERVER_URL") else None),
    }


def rassembler(etat_dir, lot_dir, jugement_path=None):
    """Copie dans `lot_dir` ce qui est publiable. Rend la liste des chemins relatifs copiés."""
    if os.path.isdir(lot_dir):
        shutil.rmtree(lot_dir)
    os.makedirs(lot_dir)
    copies = []
    for nom in A_PUBLIER:
        src = os.path.join(etat_dir, nom)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(lot_dir, nom))
            copies.append(nom)
    for d in DOSSIERS_A_PUBLIER:
        src = os.path.join(etat_dir, d)
        if os.path.isdir(src):
            os.makedirs(os.path.join(lot_dir, d), exist_ok=True)
            for f in sorted(os.listdir(src)):
                if f.endswith(".json"):
                    shutil.copy2(os.path.join(src, f), os.path.join(lot_dir, d, f))
                    copies.append(f"{d}/{f}")
    if jugement_path and os.path.exists(jugement_path):
        cible = os.path.join(lot_dir, "JUGEMENT.json")
        if os.path.abspath(jugement_path) != os.path.abspath(cible):
            shutil.copy2(jugement_path, cible)
        copies.append("JUGEMENT.json")
    return sorted(set(copies))


def publier(etat_dir, lot_dir, cle_path, sceau_path, jugement_path=None, config_path=None):
    copies = rassembler(etat_dir, lot_dir, jugement_path)
    # Assertion de CARDINAL (KE#111) : signer un lot vide, c'est signer « rien » et l'appeler preuve.
    if not copies:
        raise PublierError(
            f"ARRÊT : aucun fichier à publier depuis {etat_dir}. Un lot vide signé se lirait « tout va "
            f"bien, voici zéro fichier » : c'est le contraire de ce qu'il faut dire.")
    if "JUGEMENT.json" not in copies:
        raise PublierError(
            "ARRÊT : le lot ne porte pas son jugement. Un lot sans verdict laisse le lecteur refaire "
            "le jugement lui-même, donc autrement.")
    if "battement-passe.json" not in copies and "battement-differentiel-quotidien.json" not in copies \
            and "battement-differentiel-complet.json" not in copies:
        raise PublierError("ARRÊT : le lot ne porte AUCUN battement : il ne dit pas que l'instance vit.")

    with open(sceau_path, encoding="utf-8") as fh:
        sceau = json.load(fh)
    chaine = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as fh:
            c = json.load(fh)
        chaine = {"chain_id": c.get("chain_id"), "rewards": c.get("rewards"),
                  "deploy_block": c.get("deploy_block")}

    jug = {}
    jp = os.path.join(lot_dir, "JUGEMENT.json")
    with open(jp, encoding="utf-8") as fh:
        j = json.load(fh)
    jug = {"verdict": j.get("verdict"), "tache": j.get("tache"),
           "motifs": [m["cle"] for m in (j.get("motifs") or [])]}

    now = int(time.time())
    manifeste = {
        "schéma": SCHEMA,
        "instance": "b",
        "service": "veilleur",
        "produit_le_ts": now,
        "produit_le": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "empreinte_sources": sceau.get("empreinte_sources_attendue"),
        "release_du_paquet_scelle": (sceau.get("source") or {}).get("release"),
        "chaîne_attendue": chaine,
        "jugement": jug,
        "exécution": _contexte_execution(),
        "fichiers": {rel: sha256(os.path.join(lot_dir, rel)) for rel in copies},
        "portée": ("Ce lot est l'état publié de l'instance b du veilleur. La signature prouve qu'il "
                   "vient du détenteur de la clé d'attestation de b, et que ces octets-là n'ont pas "
                   "bougé. Elle ne prouve ni l'heure, ni qu'aucun lot ne manque, ni que la clé n'a "
                   "servi qu'ici : GitHub voit le secret, et le propriétaire du compte peut supprimer "
                   "un job. Le silence de b se juge par la surveillance, pas par ce document."),
    }

    from veilleur.attest import AttestKey
    from veilleur.verdict import canonical
    # TEST DIFFÉRENTIEL (KE#119) : `outils/verifier_lot.py` voyage seul dans la branche, sans paquet
    # `veilleur` à importer, donc il RÉIMPLÉMENTE la sérialisation canonique. Une réimplémentation ne
    # se prouve pas par « ça marche », mais par l'égalité avec la référence SUR LE DOCUMENT RÉEL.
    # Un écart ici veut dire que le lecteur calculerait d'autres octets que le signataire : on refuse
    # de signer plutôt que de publier une signature que personne ne pourra vérifier.
    from verifier_lot import _canonique as _canonique_du_verificateur
    cle = AttestKey.load(cle_path)
    payload = canonical(manifeste)
    if _canonique_du_verificateur(manifeste) != payload:
        raise PublierError(
            "ARRÊT : la sérialisation canonique de `verifier_lot.py` diffère de celle du paquet scellé "
            "sur CE manifeste. Le vérificateur calculerait d'autres octets que le signataire : la "
            "signature serait invérifiable. Rien n'est signé.")
    sig = cle.sign(DOMAINE + payload)
    enveloppe = {
        "alg": "ed25519",
        "domaine": DOMAINE.decode(),
        "clé_publique": cle.public_hex,
        "signature": sig.hex(),
        "empreinte_manifeste_sha256": hashlib.sha256(payload).hexdigest(),
        "à_savoir": "la clé publique portée ici n'authentifie personne à elle seule : elle doit être "
                    "comparée à une ANCRE posée hors de ce lot (KE#130). `outils/verifier_lot.py` "
                    "l'exige et refuse sans elle.",
    }

    for nom, doc in ((MANIFESTE, manifeste), (SIGNATURE, enveloppe)):
        p = os.path.join(lot_dir, nom)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    return {"fichiers": len(copies), "clé_publique": cle.public_hex, "verdict": jug.get("verdict")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--etat", required=True)
    ap.add_argument("--lot", required=True)
    ap.add_argument("--cle", required=True, help="CHEMIN du fichier de clé — jamais la clé elle-même")
    ap.add_argument("--sceau", default=os.path.join(ICI, "SCEAU.json"))
    ap.add_argument("--jugement", default=None)
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    try:
        rep = publier(a.etat, a.lot, a.cle, a.sceau, a.jugement, a.config)
    except PublierError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"lot publié : {rep['fichiers']} fichier(s), jugement {rep['verdict']}, "
          f"signé par {rep['clé_publique'][:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
