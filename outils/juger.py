"""Le jugement du job : ROUGE ou VERT, lu dans ce que le paquet scellé a ÉCRIT.

Pourquoi ce fichier existe
--------------------------
Le code de sortie d'une tâche planifiée du veilleur dit **la santé de la tâche**, pas ses alertes
métier : depuis l'arbitrage du 2026-09-22, une passe qui trouve une P0 sort **0** et range l'alerte
dans son battement, que la surveillance lit. C'est juste pour un service systemd surveillé en
continu ; ce serait faux pour un job GitHub Actions, où **le seul signal que quiconque regarde est la
croix rouge**. Un contrôle rouge qui laisse le job vert serait une alerte muette (KE#105).

Ce module traduit donc, et il ne recalcule RIEN : il **lit le battement écrit par le paquet scellé**.
Refaire le jugement à côté produirait deux vérités qui peuvent diverger — c'est précisément ce que
`veilleur/battement.py:sortie_de` évite en dérivant la sortie du document écrit.

Les jambes du jugement, et ce qu'elles attrapent chacune
--------------------------------------------------------
1. `battement_absent`     — aucun battement lisible : la tâche n'a pas battu, donc elle n'a pas
                            travaillé. Une absence ne se lit jamais « rien à signaler » (KE#104).
2. `battement_perime`     — le battement existe mais il est vieux : c'est celui de la passe
                            PRÉCÉDENTE, restauré depuis la branche. Sans cette jambe, un job qui
                            meurt avant d'écrire serait jugé sur le battement d'hier (KE#131 : une
                            condition satisfaite par l'inaction).
3. `compteur_non_progresse` — le compteur `passe` n'a pas augmenté. Jambe de PROGRESSION positive,
                            complémentaire de la 2 : elle tient même si les horloges mentent.
4. `instance_inattendue`  — le battement n'est pas celui de `b`.
5. `empreinte_divergente` — le code qui a battu n'est pas le code scellé (comparé au `SCEAU.json`).
6. `chaine_inattendue`    — motif propre, nommé, le plus fort : le nœud n'a pas répondu la chaîne
                            attendue, et le paquet scellé n'a RIEN lu ni attesté.
7. `tache_en_erreur`      — toute autre erreur (amorçage absent, RPC, configuration, exception).
8. `controle_rouge`       — la tâche a fait son travail et a trouvé une alerte P0 ou P1.
9. `sortie_non_nulle`     — le processus s'est terminé anormalement. **Redondance assumée et dite** :
                            `sortie_de` dérive le code de sortie du battement, donc dans le cours
                            normal cette jambe ne peut pas rougir seule. Elle couvre ce qui se passe
                            HORS de ce cours : job tué par le délai maximal, OOM, runner coupé. On ne
                            la compte pas comme une preuve indépendante (KE#76).

Un `ok` assorti d'un P2 reste VERT, et le P2 est imprimé : un job rouge à chaque passage est un job
que personne ne lit (le veilleur a tranché la même question pour ses codes de sortie).

    python3 -B outils/juger.py --etat <dossier> --tache passe --sortie <code> \
                               --sceau SCEAU.json --precedent <n> --jugement lot/JUGEMENT.json
"""
import argparse
import json
import os
import sys
import time

AGE_MAX_DEFAUT_S = 900


def _lire(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def juger(etat_dir, tache, code_sortie, sceau_path, precedent=None, age_max_s=AGE_MAX_DEFAUT_S,
          maintenant=None):
    """Rend le document de jugement. `maintenant` est explicite : il descend jusqu'au domaine de l'âge."""
    maintenant = int(time.time()) if maintenant is None else int(maintenant)
    motifs = []                      # (clé, texte) — ROUGE dès qu'il y en a un
    remarques = []
    bat_path = os.path.join(etat_dir, f"battement-{tache}.json")
    bat = None

    try:
        bat = _lire(bat_path)
    except FileNotFoundError:
        motifs.append(("battement_absent",
                       f"aucun battement {bat_path} : la tâche « {tache} » n'a pas battu. Elle n'a donc "
                       f"pas fait son travail, et une absence ne se lit pas « rien à signaler »."))
    except (OSError, ValueError) as e:
        motifs.append(("battement_absent",
                       f"battement {bat_path} illisible ({type(e).__name__} : {e}) : le job ne peut pas "
                       f"dire ce que la tâche a fait."))

    if bat is not None:
        age = maintenant - int(bat.get("ts") or 0)
        if age > age_max_s:
            motifs.append(("battement_perime",
                           f"le battement date de {age} s (limite {age_max_s} s) : c'est celui d'une passe "
                           f"PRÉCÉDENTE, restauré depuis la branche. Cette exécution n'a rien écrit."))
        if precedent is not None and int(bat.get("passe") or 0) <= int(precedent):
            motifs.append(("compteur_non_progresse",
                           f"compteur de passe {bat.get('passe')} ≤ {precedent} avant l'exécution : "
                           f"aucune passe neuve n'a été écrite."))
        if bat.get("instance") != "b":
            motifs.append(("instance_inattendue",
                           f"le battement porte l'instance « {bat.get('instance')} », pas « b ». Deux "
                           f"instances sur le même battement se masqueraient l'une l'autre."))
        if bat.get("tache") != tache:
            motifs.append(("instance_inattendue",
                           f"le battement porte la tâche « {bat.get('tache')} », pas « {tache} »."))

        # empreinte : la référence vient du SCEAU, c'est-à-dire du scellé de la famille (KE#130)
        attendue = (_lire(sceau_path) or {}).get("empreinte_sources_attendue")
        if not attendue:
            motifs.append(("empreinte_divergente",
                           f"{sceau_path} ne porte pas d'empreinte attendue : il n'y a rien à comparer."))
        elif bat.get("empreinte") != attendue:
            motifs.append(("empreinte_divergente",
                           f"le code qui a battu porte l'empreinte {str(bat.get('empreinte'))[:16]}…, le "
                           f"sceau attend {attendue[:16]}… : ce n'est pas le code scellé qui a tourné."))

        resultat, code = bat.get("resultat"), bat.get("code")
        detail = bat.get("detail")
        if resultat == "erreur" and code == "chaine_inattendue":
            motifs.append(("chaine_inattendue",
                           f"la chaîne lue n'est pas celle attendue — RIEN n'a été lu ni attesté. "
                           f"{str(detail)[:400]}"))
        elif resultat == "erreur":
            motifs.append(("tache_en_erreur",
                           f"la tâche a échoué (code « {code} ») : elle n'a pas fait son travail. "
                           f"{str(detail)[:400]}"))
        elif resultat == "refus":
            motifs.append(("controle_rouge",
                           f"contrôle ROUGE (code « {code} ») : la tâche a fait son travail et a trouvé "
                           f"une alerte. {str(detail)[:400]}"))
        elif resultat == "ok":
            if detail:
                remarques.append(f"passe ok, avec remarque : {str(detail)[:400]}")
        else:
            motifs.append(("tache_en_erreur",
                           f"résultat « {resultat} » hors contrat (BATTEMENT.md) : indécidable."))

    if int(code_sortie) != 0 and not motifs:
        motifs.append(("sortie_non_nulle",
                       f"le battement ne signale rien mais le processus est sorti en {code_sortie} : "
                       f"terminaison anormale hors du cours normal (délai maximal, OOM, runner coupé)."))
    elif int(code_sortie) != 0:
        remarques.append(f"code de sortie du paquet scellé : {code_sortie}")

    return {
        "format": 1,
        "instance": "b",
        "tache": tache,
        "juge_le_ts": maintenant,
        "juge_le": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(maintenant)),
        "verdict": "ROUGE" if motifs else "VERT",
        "motifs": [{"cle": k, "texte": t} for k, t in motifs],
        "remarques": remarques,
        "battement": bat,
        "code_sortie_paquet": int(code_sortie),
        "compteur_precedent": precedent,
        "age_max_s": age_max_s,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--etat", required=True)
    ap.add_argument("--tache", default="passe")
    ap.add_argument("--sortie", type=int, required=True)
    ap.add_argument("--sceau", required=True)
    ap.add_argument("--precedent", default=None,
                    help="compteur de passe AVANT cette exécution ; « aucun » si la branche n'en portait pas")
    ap.add_argument("--age-max-s", type=int, default=AGE_MAX_DEFAUT_S)
    ap.add_argument("--jugement", default=None, help="où écrire le document de jugement")
    a = ap.parse_args(argv)
    prec = None
    if a.precedent not in (None, "", "aucun"):
        prec = int(a.precedent)
    doc = juger(a.etat, a.tache, a.sortie, a.sceau, precedent=prec, age_max_s=a.age_max_s)
    if a.jugement:
        os.makedirs(os.path.dirname(os.path.abspath(a.jugement)), exist_ok=True)
        tmp = a.jugement + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, a.jugement)
    for r in doc["remarques"]:
        print(f"  — {r}")
    if doc["verdict"] == "VERT":
        print(f"VERT : {doc['tache']} a fait son travail (passe "
              f"{(doc.get('battement') or {}).get('passe')}, bloc "
              f"{(doc.get('battement') or {}).get('bloc')}).")
        return 0
    print(f"ROUGE : {len(doc['motifs'])} motif(s).", file=sys.stderr)
    for m in doc["motifs"]:
        print(f"  [{m['cle']}] {m['texte']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
