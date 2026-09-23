"""Interface du veilleur. Aucun secret en argument : `.env` nomme des CHEMINS, jamais des clés.

    python3 -B -m veilleur auditer-env [chemin]
    python3 -B -m veilleur clé-générer            # n'imprime QUE la clé publique
    python3 -B -m veilleur clé-publique
    python3 -B -m veilleur fenêtre                # remesure la fenêtre d'état et la cadence
    python3 -B -m veilleur surveiller [--depuis-zéro]   # absences, burn, racines, fenêtre (à la main)
    python3 -B -m veilleur passe --instance a|b [--battement-dir <dossier>] [--depuis-zéro]
                                                  # la passe PLANIFIÉE (timer 5 min) : surveillance + battement
    python3 -B -m veilleur différentiel --instance a|b --portée quotidienne|complète [--battement-dir <d>]
                                                  # cache figé == chaîne (quotidien : volume du jour ;
                                                  #                     complet : tout, hebdomadaire)
    python3 -B -m veilleur amorcer --instance a|b --tx-deploiement 0x…
                                                  # à faire DÈS le déploiement du contrat (README)
    python3 -B -m veilleur avant-postweek  --week <id> [--table <dossier|url>]
    python3 -B -m veilleur avant-opendraw  --week <id> [--table <dossier|url>]
    python3 -B -m veilleur confirmer --bloc <n> --hash 0x…
    python3 -B -m veilleur vérifier <verdict.json> [--clé-publique <hex|fichier>]
                                                  # l'ancre de confiance est HORS de l'enveloppe
    python3 -B -m veilleur compte-à-rebours          # échéances J+90 / J+30, TOUJOURS rendues
    python3 -B -m veilleur vérifier-publiquement --table <fichier|url> [--rpc <url>]
                                                    # LE point d'entrée d'un tiers : ni .env, ni clé

Codes de sortie : 0 = GO, 10 = REFUS, 20 = INDISPONIBLE, 2 = erreur de configuration ou d'exécution.
Aucun autre chemin ne rend 0. « Je n'ai pas pu vérifier » ne doit jamais ressembler à « tout va bien ».

Tâches PLANIFIÉES (`passe`, `différentiel`, arbitrage du 2026-09-22) : la sortie dit la SANTÉ de la tâche, pas
l'existence d'alertes métier — 0 si elle a fait son travail (battement `ok` ou `refus`), 20 si une section n'a pu
être vérifiée, 2 sinon (dont `chaine_inattendue`, `amorcage_absent`). Les alertes métier (P0, P1) vivent dans le
battement, que la surveillance lit. La sortie est DÉRIVÉE du battement écrit (`battement.sortie_de`).
"""
import argparse
import json
import sys

from .attest import AttestError
from .config import ConfigError, Settings, audit_env_file
from .verdict import EXIT_CODES


def _settings():
    return Settings.load()


def _ancre_du_env():
    """Chemin de l'ancre de confiance, tel que `.env` le nomme. `vérifier` doit rester utilisable par
    un signataire du Safe qui n'a PAS notre `.env` : un `.env` illisible n'est donc pas une erreur
    ici, c'est simplement une ancre absente — et `charger_cle_de_confiance` refusera bruyamment."""
    try:
        return _settings().attest_pubkey_file
    except Exception:  # noqa: BLE001 - pas de .env chez le tiers, ce n'est pas une panne
        return None


def _veilleur(s):
    from .chainabi import RewardsModel
    from .service import Veilleur
    return Veilleur(s, RewardsModel(s.contracts_dir))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="veilleur", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("auditer-env")
    p.add_argument("chemin", nargs="?")
    sub.add_parser("clé-générer")
    sub.add_parser("clé-publique")
    sub.add_parser("fenêtre")
    p = sub.add_parser("surveiller")
    p.add_argument("--depuis-zéro", action="store_true",
                   help="reconstruction COMPLÈTE depuis le bloc de déploiement, sans cache")
    p = sub.add_parser("passe")
    p.add_argument("--instance", required=True, choices=("a", "b"))
    p.add_argument("--battement-dir", default=None,
                   help="dossier des battements et de health.json ; prioritaire sur le .env (pour battre "
                        "même quand le .env est illisible)")
    p.add_argument("--depuis-zéro", action="store_true")
    p = sub.add_parser("différentiel")
    p.add_argument("--instance", required=True, choices=("a", "b"))
    p.add_argument("--portée", default="complète", choices=("quotidienne", "complète"))
    p.add_argument("--battement-dir", default=None)
    p = sub.add_parser("amorcer")
    p.add_argument("--instance", required=True, choices=("a", "b"))
    p.add_argument("--tx-deploiement", required=True,
                   help="hash de la transaction de déploiement de SpindexRewards (public)")
    for nom in ("avant-postweek", "avant-opendraw"):
        p = sub.add_parser(nom)
        p.add_argument("--week", type=int, required=True)
        p.add_argument("--table", default=None, help="dossier local ou base https ; défaut : .env")
        p.add_argument("--sans-écriture", action="store_true")
    p = sub.add_parser("confirmer")
    p.add_argument("--bloc", type=int, required=True)
    p.add_argument("--hash", required=True)
    p = sub.add_parser("vérifier")
    p.add_argument("fichier")
    # L'ancre de confiance vit HORS de l'enveloppe. Sans elle, n'importe qui fabrique un « GO »
    # valide en signant son propre document (KE#130). Le chemin peut venir du `.env`
    # (`SPINDEX_ATTEST_PUBKEY_FILE`) ; à défaut la commande REFUSE plutôt que de se rabattre sur la
    # clé transportée par le document qu'elle vérifie.
    p.add_argument("--clé-publique", dest="cle_publique", default=None,
                   help="clé publique ATTENDUE : 64 caractères hexadécimaux, ou chemin d'un fichier "
                        "d'ancrage. Défaut : SPINDEX_ATTEST_PUBKEY_FILE du .env.")
    # LE point d'entrée public : (table, URL RPC) → le même verdict que nous. Aucun `.env`, aucune
    # clé, aucun chemin de notre infrastructure. C'est cette commande qu'un tiers exécute.
    p = sub.add_parser("vérifier-publiquement")
    p.add_argument("--table", required=True, help="chemin local ou URL https de la table publiée")
    p.add_argument("--rpc", default=None,
                   help="URL RPC ; ABSENTE ⇒ portée « table seule » (rejouable pour toujours)")
    p.add_argument("--artefacts", default=None, help="racine d'artefacts ; défaut : le lot embarqué")
    p.add_argument("--rewards", default=None)
    p.add_argument("--deploy-block", type=int, default=None)
    p.add_argument("--chain-id", type=int, default=None)
    p.add_argument("--sortie", default=None)
    p = sub.add_parser("compte-à-rebours")

    a = ap.parse_args(argv)

    try:
        if a.cmd == "auditer-env":
            ok, bad = audit_env_file(a.chemin or _env_default())
            if ok:
                print("OK : toutes les valeurs sont entre apostrophes simples (KE#107).")
                return 0
            for i, k, why in bad:
                print(f"ÉCHEC ligne {i} : {k} — {why}", file=sys.stderr)
            return 2

        if a.cmd == "clé-générer":
            from .attest import AttestKey
            s = _settings()
            k = AttestKey.generate(s.attest_key_file)
            print("Clé d'attestation Ed25519 créée. Le secret n'est PAS imprimé.")
            print("clé publique :", k.public_hex)
            print("À publier auprès des signataires du Safe : c'est elle qui rend un feu vert opposable.")
            print("Chacun la pose chez lui comme ANCRE DE CONFIANCE — fichier nommé par "
                  "SPINDEX_ATTEST_PUBKEY_FILE, ou `vérifier --clé-publique <hex>`. Sans ancre, "
                  "`vérifier` refuse : une signature vérifiée contre la clé que le document porte "
                  "n'authentifie personne.")
            return 0

        if a.cmd == "clé-publique":
            from .attest import AttestKey
            s = _settings()
            print(AttestKey.load(s.attest_key_file).public_hex)
            return 0

        if a.cmd == "vérifier":
            from .verdict import CleInattendue, charger_cle_de_confiance, verify_envelope
            env = json.load(open(a.fichier, encoding="utf-8"))
            ancre = a.cle_publique or _ancre_du_env()
            # Résolue AVANT d'imprimer quoi que ce soit : sans ancre, la commande ne doit rien
            # afficher qui ressemble à une attestation (KE#105).
            attendue = charger_cle_de_confiance(ancre)
            try:
                ok = verify_envelope(env, clé_publique_attendue=attendue)
            except CleInattendue as e:
                print(str(e), file=sys.stderr)
                print(json.dumps({"signature_valide": False, "clé_inattendue": True,
                                  "clé_publique_du_document": (env.get("signature") or {})
                                  .get("clé_publique"),
                                  "clé_publique_attendue": attendue},
                                 ensure_ascii=False, indent=1))
                return 2
            d = env["document"]
            eng = d["engagement"]
            print(json.dumps({
                "signature_valide": ok, "verdict": d["verdict"], "action": d["action"],
                "racine": eng.get("racine"), "émis_le": d["émis_le"],
                "clé_publique_attendue": attendue,
                # Le contexte LIÉ : un feu vert n'a de sens que pour une chaîne, un contrat et un
                # instantané donnés. Les imprimer évite qu'un verdict d'un autre déploiement soit
                # présenté ici sans que personne ne le voie.
                "chainId": ((d.get("contexte") or {}).get("chaîne") or {}).get("chainId"),
                "rewards": ((d.get("contexte") or {}).get("chaîne") or {}).get("rewards"),
                "bloc_instantané": eng.get("snapshotBlock"),
                "hash_instantané": eng.get("snapshotBlockHash"),
            }, ensure_ascii=False, indent=1))
            if not ok:
                print("ÉCHEC : signature invalide.", file=sys.stderr)
                return 2
            return EXIT_CODES[d["verdict"]]

        if a.cmd == "vérifier-publiquement":
            # Ce chemin ne touche NI `.env`, NI clé, NI `contracts/` : c'est la condition pour qu'un
            # tiers puisse rejouer nos verdicts, et le banc l'exécute depuis un dossier vierge.
            from .public_verify import verifier
            env = verifier(a.table, rpc_url=a.rpc, racine_artefacts=a.artefacts,
                           surcharges_chaine={"rewards": a.rewards, "deploy_block": a.deploy_block,
                                              "chain_id": a.chain_id})
            txt = json.dumps(env, ensure_ascii=False, indent=1)
            if a.sortie:
                with open(a.sortie, "w", encoding="utf-8") as fh:
                    fh.write(txt + "\n")
            print(txt)
            d = env["document"]
            print(f"\n=== {d['verdict']} ({d['portée_technique']}) === "
                  f"empreinte reproductible : {d['empreinte_reproductible']}", file=sys.stderr)
            return EXIT_CODES[d["verdict"]]

        if a.cmd == "passe":
            return _executer(a, "passe")

        if a.cmd == "différentiel":
            return _executer(a, "differentiel-quotidien" if a.portée == "quotidienne"
                             else "differentiel-complet")

        s = _settings()
        if getattr(a, "depuis_zéro", False):
            s.reprise = "complet"
        v = _veilleur(s)

        if a.cmd == "amorcer":
            from .amorcage import amorcer
            if s.instance and s.instance != a.instance:
                raise ConfigError(f"ARRÊT : le .env déclare l'instance « {s.instance} », pas « {a.instance} ».")
            rep = amorcer(v, s, a.tx_deploiement)
            print(json.dumps(rep, ensure_ascii=False, indent=1))
            print(f"\n=== {rep['état']} ===", file=sys.stderr)
            return 0 if rep["état"] == "AMORCÉ" else 10

        if a.cmd == "compte-à-rebours":
            rep = v.surveillance()["compte_à_rebours"]
            print(json.dumps(rep, ensure_ascii=False, indent=1))
            return {"P0": 10, "P1": 20}.get(rep.get("pire_gravité"), 0)

        if a.cmd == "fenêtre":
            from .window_history import WindowHistory, mesurer_fenetre
            w = mesurer_fenetre(v.reader)
            h = WindowHistory(s.state_dir)
            al = h.alertes(w, s.window_alert_s, besoin_s=s.window_need_s)
            h.ajouter(w).save()
            print(json.dumps({"mesure": w, "meilleure_relevée_s": h.meilleure_s,
                              "besoin_s": s.window_need_s, "alertes": al}, ensure_ascii=False, indent=1))
            return {"P0": 10, "P1": 20}.get(next((g for g in ("P0", "P1")
                                                 if any(x["gravité"] == g for x in al)), None), 0)

        if a.cmd == "surveiller":
            rep = v.surveillance()
            print(json.dumps(rep, ensure_ascii=False, indent=1))
            return code_de_sortie(rep)

        if a.cmd in ("avant-postweek", "avant-opendraw"):
            env = (v.check_postweek if a.cmd == "avant-postweek" else v.check_opendraw)(
                a.week, a.table)
            d = env["document"]
            if not a.sans_écriture:
                from .verdict import write as write_verdict
                path = write_verdict(env, s.state_dir)
                print(f"verdict écrit : {path}", file=sys.stderr)
            print(json.dumps(env, ensure_ascii=False, indent=1))
            print(f"\n=== {d['verdict']} === motifs : {d['contrôles'].get('motifs')}", file=sys.stderr)
            return EXIT_CODES[d["verdict"]]

        if a.cmd == "confirmer":
            rep = v.confirmer(a.bloc, a.hash)
            print(json.dumps(rep, ensure_ascii=False, indent=1))
            # CADUC est un P0 selon le code lui-même : il ne sort JAMAIS 0 (défaut V5).
            return {"CONFIRMÉ": 0, "CADUC": 10, "PAS_ENCORE": 20}.get(rep["état"], 2)

    except (ConfigError, AttestError) as e:
        print(str(e), file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"ÉCHEC : {type(e).__name__} : {e}", file=sys.stderr)
        return 2
    return 2


def code_de_sortie(rep):
    """Commande À LA MAIN `surveiller` : 10 sur P0 ; 20 sur P1 ou section en échec ; 0 sinon.

    Les tâches PLANIFIÉES ne passent plus par ici (arbitrage 2026-09-22) : leur sortie dit leur santé et se
    dérive du battement (`battement.sortie_de`) ; un opérateur qui lance `surveiller` veut, lui, le verdict.

    Les avertissements PERMANENTS (`fenêtre_sous_seuil`), les INFO et les P2 ne changent pas le code :
    une sortie qui vaut 20 à chaque passe, quoi qu'il arrive, est un code que personne ne lit (V2).
    """
    g = {x.get("gravité") for x in rep.get("alertes", [])}
    if "P0" in g:
        return 10
    if "P1" in g or rep.get("sections_en_échec"):
        return 20
    return 0


def _travail(tache, v, s):
    """Le travail d'une tâche. Rend (rapport, bloc de tête lu, resultat, code, detail).

    Plus de code de sortie ici : il est dérivé du battement ÉCRIT (`_executer`), pour qu'aucun chemin ne
    puisse faire sortir la tâche en échec avec un battement `ok`, ni l'inverse.
    """
    from .battement import qualifier, qualifier_differentiel
    if tache == "passe":
        rep = v.surveillance()              # la garde de chaîne est sa PREMIÈRE lecture
        r, c, d = qualifier(rep)
        return rep, rep.get("bloc_tête"), r, c, d
    from .journaux import differentiel, differentiel_quotidien
    garde = v.garde_chaine(exiger_amorcage=True)       # AVANT toute lecture du différentiel
    head, fin_bn, fin_hash, _ = v.chaine_passe()
    fn = differentiel_quotidien if tache == "differentiel-quotidien" else differentiel
    rep = fn(v.client, s, head, fin_bn, fin_hash)
    rep["chaîne"] = garde
    r, c, d = qualifier_differentiel(rep)
    return rep, head, r, c, d


def _executer(a, tache):
    """Une tâche PLANIFIÉE : le travail, puis — et seulement puis — la durée, le battement de CETTE tâche
    et `health.json` (BATTEMENT.md v1.2). Y compris en échec."""
    import os
    import time
    from .battement import Battement, BattementError, ecrire_health, enregistrer_duree, sortie_de
    from .journaux import _ecrire_atomique

    bat = None
    bloc = None
    rpc = {}
    tete = deploiement = cadence = None
    plan = plani = None
    t0 = time.time()
    try:
        s = _settings()
        deploiement = s.deploy_block
        # Lus AVANT le travail : `health.json` publie la cadence DÉCLARÉE par CETTE instance (5 min sous
        # systemd pour `a`, 15 min sur GitHub Actions pour `b`). Sans eux, il n'est pas réécrit du tout.
        plan, plani = s.planification, s.planificateur
        if s.instance and s.instance != a.instance:
            raise ConfigError(f"ARRÊT : le .env déclare l'instance « {s.instance} », l'unité lance "
                              f"« {a.instance} ». Deux instances ne partagent ni état ni battement.")
        if getattr(a, "depuis_zéro", False):
            s.reprise = "complet"
        bat = Battement(a.battement_dir or s.battement_dir, a.instance, tache)
        v = _veilleur(s)
        try:
            rep, bloc, resultat, code, detail = _travail(tache, v, s)
        finally:
            rpc = dict(getattr(v.client, "stats", {}) or {})
        tete = bloc
        cadence = ((rep.get("fenêtre_état") or {}).get("cadence") or {}).get("blocs_par_s")
        rep["instance"] = a.instance
        rep["tâche"] = tache
        rep["mode_de_lecture"] = s.reprise
        _ecrire_atomique(os.path.join(s.state_dir, f"derniere-{tache}.json"), rep)
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    except (ConfigError, AttestError, BattementError) as e:
        print(str(e), file=sys.stderr)
        resultat, code, detail = "erreur", "configuration", str(e)[:400]
    except Exception as e:  # noqa: BLE001
        from .rpc import RpcUnavailable
        print(f"ÉCHEC : {type(e).__name__} : {e}", file=sys.stderr)
        resultat = "erreur"
        # `chaine_inattendue` / `amorcage_absent` : code DÉDIÉ porté par l'exception de la garde.
        code = getattr(e, "code_battement", None) or (
            "rpc_error" if isinstance(e, RpcUnavailable) else "exception:" + type(e).__name__)
        detail = str(e)[:400]
    # ---- APRÈS le travail, y compris en échec : durée, battement de la tâche, health.json
    if bat is None and a.battement_dir:
        try:
            bat = Battement(a.battement_dir, a.instance, tache)
        except BattementError as e:
            print(str(e), file=sys.stderr)
    if bat is None:
        print("AUCUN BATTEMENT ÉCRIT : dossier inconnu (ni --battement-dir, ni .env lisible). La "
              "surveillance verra cette tâche MUETTE, ce qui est exact.", file=sys.stderr)
        return 2                            # sans battement, jamais 0 : rien ne dit que la tâche a travaillé
    # Durée et health.json AVANT le battement : un échec de leur écriture devient une ERREUR de la tâche, dite
    # par le battement ET par la sortie — il ne peut plus faire sortir 2 derrière un battement `ok`.
    try:
        enregistrer_duree(bat.dossier, tache, time.time() - t0)
        if plan is None:
            # La configuration n'a pas pu être lue : la cadence déclarée de cette instance est INCONNUE.
            # Réécrire `health.json` avec une cadence choisie ici serait exactement le défaut corrigé le
            # 2026-09-23. On ne le réécrit PAS, et on le DIT (KE#105) ; le battement, lui, est écrit et
            # porte le motif, donc la surveillance verra l'échec sans lire un `health.json` inventé.
            print("health.json NON réécrit : la planification déclarée de l'instance est inconnue "
                  "(configuration illisible). L'ancien health.json reste en place et vieillit ; le "
                  "battement porte le motif.", file=sys.stderr)
        else:
            ecrire_health(bat.dossier, a.instance, tete=tete, deploiement=deploiement, cadence=cadence,
                          planification=plan, planificateur=plani)
    except Exception as e:  # noqa: BLE001
        print(f"ÉCHEC health.json : {type(e).__name__} : {e}", file=sys.stderr)
        resultat, code = "erreur", "health_non_ecrit"
        detail = f"durées / health.json non écrits : {type(e).__name__} : {e}"[:400]
    doc = bat.ecrire(resultat, code, detail, bloc, rpc=rpc)
    print(f"battement {tache} : passe {doc['passe']} {doc['resultat']} {doc['code'] or ''} "
          f"({time.strftime('%H:%M:%S')})", file=sys.stderr)
    return sortie_de(doc)


def _env_default():
    import os
    return os.environ.get("SPINDEX_VEILLEUR_ENV") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".env")


if __name__ == "__main__":
    sys.exit(main())
