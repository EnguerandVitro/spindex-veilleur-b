"""Le compte à rebours J+90 / J+30 — **alerte de premier rang, indépendante de l'état du veilleur**.

Pourquoi ce module est séparé de `longfuse.py`
-----------------------------------------------
`longfuse.py` alerte quand une semaine dépasse un SEUIL d'âge. C'est une alerte d'anomalie : elle se
tait tant que tout va bien. Or le dommage, ici, ne vient pas d'une anomalie — il vient du TEMPS qui
passe pendant que tout va bien. Une semaine versée, un veilleur en panne, un Safe qui s'abstient
conformément à la règle : rien n'est anormal, et au 90e jour l'argent des joueurs retourne au Safe.

Le compte à rebours est donc rendu **à chaque passage, pour chaque échéance ouverte, quel que soit
l'état du reste** — y compris quand tous les autres contrôles sont `INDISPONIBLE`. Il ne doit jamais
être atteint *en silence*.

Deux propriétés qui le distinguent d'une alerte ordinaire :

1. **la gravité se DÉRIVE des jours restants**, elle n'est pas un seuil choisi : plus l'échéance
   approche, plus elle monte, et elle finit en P0. Un compte à rebours dont la gravité ne bouge pas
   est un compte à rebours que personne ne regarde ;
2. **l'absence d'échéance est un ÉTAT NOMMÉ**, pas un silence. `AUCUNE_ÉCHÉANCE_OUVERTE` dit qu'on a
   énuméré et qu'il n'y avait rien ; `NON_CALCULABLE` dit qu'on n'a pas pu regarder. Les deux ne se
   confondent jamais (KE#105).

Un déploiement SANS semaine (arbitrage du 2026-09-22)
-----------------------------------------------------
Avant la première semaine, il n'existe AUCUN journal d'échéance : c'était rendu `NON_CALCULABLE` en P1, donc une P1
PERMANENTE sur tout déploiement neuf (testnet 46630, rapport §5) — une alerte que plus personne ne lit. Or zéro
échéance n'y veut pas dire « je n'ai pas pu regarder » si l'on PROUVE que la lecture voit le contrat : c'est le
témoin positif de l'amorçage (preuve B, KE#121), le journal du constructeur `OwnershipTransferred(0x0, …)` émis au
bloc de déploiement. D'où trois cas, jamais confondus :

- aucun journal lu du tout, ou pas de témoin : `NON_CALCULABLE`, P1 — la lecture peut être aveugle ;
- témoin présent, zéro échéance, déploiement récent : `AUCUNE_SEMAINE_DEPUIS_LE_DÉPLOIEMENT`, INFO explicite ;
- même chose au-delà de `BORNE_PREMIERE_SEMAINE_S` : même état, mais P1 — la cadence hebdomadaire n'est pas tenue.

La borne est DÉRIVÉE de la cadence de la spec (REWARDS_SPEC §3 : « Chaque semaine, le Safe dépose […] puis publie
`postWeek` ») : la semaine en cours au déploiement se clôt au plus tard UNE période après lui, et son versement
tombe au plus tard avant la clôture de la suivante. Au-delà de DEUX périodes sans aucun `WeekFunded`, au moins une
semaine close n'a pas été versée à la cadence de la spec. L'horloge est celle de la CHAÎNE (horodatage du bloc de
déploiement, `finalized_ts`), jamais l'horloge murale, sauf repli hors ligne dit comme tel.
"""
from .chainabi import decode_event

ECHEANCES = ("WeekFunded", "WeekPosted", "WeekSwept", "DrawOpened", "DrawSettled",
             "PrizeClaimed", "PrizeReturned")

# Paliers dérivés des jours RESTANTS. Le dernier palier est P0 : une échéance à moins d'une semaine
# qui n'a pas de décision humaine derrière elle est un incident, pas un indicateur.
PALIERS = ((7, "P0"), (14, "P0"), (30, "P1"), (60, "P2"), (10 ** 9, "INFO"))

# Cadence de la spec (REWARDS_SPEC §3, « Chaque semaine ») et borne DÉRIVÉE (docstring du module).
SEMAINE_S = 7 * 86_400
BORNE_PREMIERE_SEMAINE_S = 2 * SEMAINE_S


def gravite(jours_restants):
    """Gravité DÉRIVÉE des jours restants.

    Il y avait ici un `if jours_restants <= 0: return "P0"` pour le cas de l'échéance dépassée. La
    passe de cassures l'a montré INERTE : le premier palier est `(7, "P0")`, et toute valeur ≤ 7 —
    négative comprise — y tombe déjà. Un garde-fou que rien ne peut faire rougir est du décor, pas
    une protection (KE#129) ; il est retiré plutôt que conservé « au cas où », et sa raison d'être
    est écrite ici pour que personne ne le réintroduise.
    """
    if jours_restants is None:
        return "P1"
    for seuil, g in PALIERS:
        if jours_restants <= seuil:
            return g
    return "INFO"


def _index(model, logs, block_ts):
    abi = model.abi
    topics = {abi.topic0(n).lower(): n for n in ECHEANCES}
    out = {}
    n_vus = 0
    for lg in logs:
        name = topics.get(lg["topics"][0].lower())
        if name is None:
            continue
        ev = decode_event(abi, name, lg)
        n_vus += 1
        bn = int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"]
        rec = out.setdefault(ev["weekId"], {})
        rec.setdefault(name, []).append(block_ts(bn))
    return out, n_vus


def _temoin_constructeur(model, logs, deploy_block):
    """Le journal `OwnershipTransferred(0x0, …)` du constructeur, au bloc de déploiement : preuve que la lecture
    voit le contrat (même témoin que la preuve B de l'amorçage)."""
    t0 = model.abi.topic0("OwnershipTransferred").lower()
    for lg in logs:
        tp = lg.get("topics") or []
        bn = int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"]
        if len(tp) > 1 and tp[0].lower() == t0 and int(tp[1], 16) == 0 and bn == int(deploy_block):
            return True
    return False


def calculer(model, logs, now_ts, block_ts, *, deploy_block):
    """Rend TOUTES les échéances ouvertes, avec leurs jours restants. Jamais filtré par un seuil.

    `deploy_block` est OBLIGATOIRE et nommé (KE#62) : sans lui, le cas « aucune semaine depuis le déploiement »
    ne peut pas être prouvé et retomberait, en silence, soit en P1 permanente, soit en « rien à signaler ».
    """
    idx, n_vus = _index(model, logs, block_ts)
    claim_window = model.c["CLAIM_WINDOW"]
    prize_window = model.c["PRIZE_WINDOW"]
    echeances = []

    for wid in sorted(idx):
        rec = idx[wid]
        if "WeekFunded" in rec and "WeekSwept" not in rec:
            # §11.7 : les 90 jours courent depuis la PUBLICATION, ou depuis le VERSEMENT si la
            # semaine n'a jamais été publiée. Le second cas est le piège : il est le plus court.
            base = min(rec["WeekPosted"]) if "WeekPosted" in rec else min(rec["WeekFunded"])
            echeance = base + claim_window
            jours = (echeance - now_ts) / 86400.0
            echeances.append({
                "type": "balayage_de_semaine",
                "weekId": str(wid),
                "publiée": "WeekPosted" in rec,
                "départ_de_l_horloge": "publication" if "WeekPosted" in rec else "VERSEMENT",
                "échéance_ts": echeance,
                "jours_restants": round(jours, 2),
                # Gravité DÉRIVÉE seulement pour le PIÈGE (semaine jamais publiée). Une semaine
                # publiée dont le délai de réclamation court est le fonctionnement NORMAL : la dériver
                # aussi mettait le veilleur en P0 permanent (14 jours avant chaque balayage normal,
                # soit toujours au moins une semaine sur treize), c'est-à-dire en alerte que plus
                # personne ne lit. Elle reste RENDUE, en INFO.
                "gravité": gravite(jours) if "WeekPosted" not in rec else "INFO",
                "conséquence": (
                    "au terme, `sweepWeek` rend le reliquat au Safe."
                    if "WeekPosted" in rec else
                    "au terme, `sweepWeek` rend l'enveloppe au Safe SANS QU'AUCUN JOUEUR AIT PU "
                    "RÉCLAMER — la semaine n'a jamais été publiée."),
                "action": ("publier la semaine (`postWeek`) avant l'échéance"
                           if "WeekPosted" not in rec else "aucune, c'est le fonctionnement normal"),
            })
        if "DrawOpened" in rec and "PrizeClaimed" not in rec and "PrizeReturned" not in rec:
            base = min(rec["DrawSettled"]) if "DrawSettled" in rec else min(rec["DrawOpened"])
            echeance = base + prize_window
            jours = (echeance - now_ts) / 86400.0
            echeances.append({
                "type": "retour_de_dotation",
                "weekId": str(wid),
                "réglé": "DrawSettled" in rec,
                "départ_de_l_horloge": "règlement" if "DrawSettled" in rec else "OUVERTURE",
                "échéance_ts": echeance,
                "jours_restants": round(jours, 2),
                # Tirage RÉGLÉ non réclamé : pas un piège de la maison, mais de l'argent de JOUEUR qui
                # repart au Safe à J+30 (arbitrage Q2). Alerte dédiée P2, séparée du flux INFO.
                "gravité": gravite(jours) if "DrawSettled" not in rec else "P2",
                "conséquence": (
                    "au terme, `returnPrize` rend la dotation au Safe faute de réclamation."
                    if "DrawSettled" in rec else
                    "au terme, `returnPrize` rend la dotation au Safe SANS GAGNANT — le tirage n'a "
                    "jamais été réglé."),
                "action": ("régler le tirage (`settleDraw`, ouvert à TOUS) avant l'échéance"
                           if "DrawSettled" not in rec else "le gagnant doit réclamer"),
            })

    if n_vus == 0 and _temoin_constructeur(model, logs, deploy_block):
        age = now_ts - block_ts(int(deploy_block))
        depasse = age > BORNE_PREMIERE_SEMAINE_S
        return {"état": "AUCUNE_SEMAINE_DEPUIS_LE_DÉPLOIEMENT",
                "explication": (f"aucune semaine versée ni publiée dans les journaux FINALISÉS depuis le "
                                f"déploiement (bloc {deploy_block}, il y a {age / 86400.0:.2f} j) ; lecture PROUVÉE "
                                f"par le journal du constructeur. "
                                + ("La borne de première semaine est DÉPASSÉE : la cadence hebdomadaire de la spec "
                                   "n'est pas tenue." if depasse else
                                   "État normal avant la première semaine.")
                                + f" Bascule en P1 au-delà de {BORNE_PREMIERE_SEMAINE_S // 86400} j (2 × la "
                                  f"période hebdomadaire de REWARDS_SPEC §3)."),
                "échéances": [], "pire_gravité": "P1" if depasse else "INFO", "semaines_énumérées": 0,
                "âge_du_déploiement_s": age, "borne_s": BORNE_PREMIERE_SEMAINE_S}
    if n_vus == 0:
        return {"état": "NON_CALCULABLE",
                "explication": "aucun journal d'échéance n'a été lu. Ce n'est PAS « aucune échéance "
                               "ouverte » : c'est « je n'ai pas pu regarder » (KE#105).",
                "échéances": [], "pire_gravité": "P1", "semaines_énumérées": 0}
    if not echeances:
        return {"état": "AUCUNE_ÉCHÉANCE_OUVERTE",
                "explication": f"{len(idx)} semaine(s)/tirage(s) énumérés, aucune échéance en cours.",
                "échéances": [], "pire_gravité": "INFO", "semaines_énumérées": len(idx)}

    echeances.sort(key=lambda e: e["jours_restants"])
    ordre = {"P0": 0, "P1": 1, "P2": 2, "INFO": 3}
    pire = min((e["gravité"] for e in echeances), key=lambda g: ordre[g])
    return {"état": "COMPTE_À_REBOURS",
            "explication": "rendu à CHAQUE passage, pour chaque échéance ouverte, quel que soit "
                           "l'état du reste du veilleur. Le dommage ici vient du temps qui passe "
                           "pendant que tout va bien.",
            "échéances": echeances, "pire_gravité": pire,
            "semaines_énumérées": len(idx),
            "prochaine_échéance_jours": echeances[0]["jours_restants"]}


def alertes(rapport):
    """Convertit le compte à rebours en alertes. Tout ce qui n'est pas INFO en est une."""
    if rapport["état"] == "NON_CALCULABLE":
        return [{"gravité": "P1", "source": "compte à rebours",
                 "clé": "compte_a_rebours_non_calculable", "motif": rapport["explication"]}]
    if rapport["état"] == "AUCUNE_SEMAINE_DEPUIS_LE_DÉPLOIEMENT":
        if rapport["pire_gravité"] == "INFO":
            return []
        return [{"gravité": "P1", "source": "compte à rebours",
                 "clé": "aucune_semaine_depuis_le_deploiement", "motif": rapport["explication"],
                 "action": "verser puis publier la première semaine (`fundWeek`, `postWeek`)"}]
    out = []
    for e in rapport["échéances"]:
        if e["gravité"] == "INFO":
            continue
        if e["type"] == "retour_de_dotation" and e.get("réglé"):
            out.append({"gravité": "P2", "source": "lot gagnant non réclamé",
                        "clé": f"lot_gagnant_non_reclame:{e['weekId']}",
                        "motif": f"lot gagnant du tirage {e['weekId']} non réclamé : {e['jours_restants']} "
                                 f"jours avant l'échéance J+30 (échéance_ts {e['échéance_ts']}).",
                        "échéance_ts": e["échéance_ts"], "jours_restants": e["jours_restants"],
                        "conséquence": e["conséquence"],
                        "action": "prévenir le gagnant : c'est de l'argent de JOUEUR qui repart au Safe."})
            continue
        out.append({"gravité": e["gravité"], "source": "compte à rebours",
                    "clé": f"{e['type']}:{e['weekId']}",
                    "motif": f"{e['jours_restants']} jours avant l'échéance (horloge partie de la "
                             f"{e['départ_de_l_horloge']}).",
                    "conséquence": e["conséquence"], "action": e["action"]})
    return out
