"""Surveillance des ABSENCES : les deux pièges à mèche longue, et la racine qui change après réorg.

Ces trois-là ne se voient pas en regardant ce qui arrive. Ce sont des NON-ÉVÉNEMENTS, et le
bénéficiaire du silence est la maison :

  - une semaine **versée mais jamais publiée** voit son horloge de balayage courir depuis le
    VERSEMENT (§11.7) : au 90e jour le Safe peut `sweepWeek` et l'argent des joueurs retourne au Safe
    **sans qu'aucun joueur ait pu réclamer** ;
  - un `openDraw` **jamais réglé** rend la dotation au Safe au 30e jour, **sans gagnant** — les 30
    jours courent depuis l'OUVERTURE si le tirage n'a jamais été réglé. `settleDraw` est ouvert à
    tous, donc n'importe qui peut sauver le tirage : encore faut-il que quelqu'un regarde ;
  - un `WeekPosted` qui RÉAPPARAÎT avec une AUTRE racine après réorganisation est un **P0**, pas un
    artefact : `postWeek` n'est pas rejouable (`if (w.root != bytes32(0)) revert`), donc deux racines
    pour un même `weekId` signifient nécessairement que deux transactions ont été soumises.

Ce sont des contrôles de COUVERTURE (KE#111 appliqué à la surveillance) : la requête ÉNUMÈRE les
`weekId` connus et COMPTE ceux sans contrepartie. Un compte de zéro sur un ensemble vide n'est pas
un « rien à signaler » : il est rendu comme l'état explicite `AUCUNE_SEMAINE_CONNUE`.
"""
import json
import os

from .chainabi import decode_event

WEEK_EVENTS = ("WeekFunded", "WeekPosted", "WeekSwept")
DRAW_EVENTS = ("DrawOpened", "DrawSettled", "PrizeClaimed", "PrizeReturned")


def _index(model, logs, names, block_ts):
    abi = model.abi
    topics = {abi.topic0(n).lower(): n for n in names}
    out = {}
    counts = {n: 0 for n in names}
    for lg in logs:
        name = topics.get(lg["topics"][0].lower())
        if name is None:
            continue
        ev = decode_event(abi, name, lg)
        counts[name] += 1
        wid = ev["weekId"]
        bn = int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"]
        rec = out.setdefault(wid, {"weekId": wid})
        rec.setdefault(name, []).append({
            "bloc": bn, "ts": block_ts(bn), "ev": ev,
            "blockHash": lg.get("blockHash"), "transactionHash": lg.get("transactionHash"),
        })
    return out, counts


def weeks_report(model, logs, now_ts, alert_days, block_ts):
    """Semaines versées et jamais publiées. Rend un rapport à COUVERTURE explicite."""
    idx, counts = _index(model, logs, WEEK_EVENTS, block_ts)
    claim_window = model.c["CLAIM_WINDOW"]
    if not idx:
        return {"état": "AUCUNE_SEMAINE_CONNUE",
                "explication": "aucun `WeekFunded` n'a été vu sur la plage examinée. Ce n'est PAS "
                               "« rien à signaler » : c'est une absence de données, et elle se dit.",
                "semaines_énumérées": 0, "alertes": [], "compteurs": counts}
    alertes = []
    for wid in sorted(idx):
        rec = idx[wid]
        if "WeekFunded" not in rec:
            continue
        funded_ts = min(x["ts"] for x in rec["WeekFunded"])
        posted = "WeekPosted" in rec
        swept = "WeekSwept" in rec
        if posted or swept:
            continue
        age_j = (now_ts - funded_ts) / 86400.0
        if age_j >= alert_days:
            balayable_le = funded_ts + claim_window
            alertes.append({
                "gravité": "P1",
                "weekId": str(wid),
                "versée_le_ts": funded_ts,
                "âge_jours": round(age_j, 2),
                "balayable_à_partir_de_ts": balayable_le,
                "jours_avant_balayage": round((balayable_le - now_ts) / 86400.0, 2),
                "conséquence": "au 90e jour, `sweepWeek` rend l'enveloppe au Safe sans qu'aucun joueur "
                               "ait pu réclamer.",
            })
    # Assertion de COUVERTURE : on a bien énuméré, et on dit combien.
    return {"état": "COUVERTURE_OK", "semaines_énumérées": len(idx),
            "semaines_sans_publication": sum(1 for w in idx.values()
                                             if "WeekFunded" in w and "WeekPosted" not in w
                                             and "WeekSwept" not in w),
            "alertes": alertes, "compteurs": counts}


def draws_report(model, logs, now_ts, alert_days, block_ts):
    """Tirages ouverts et jamais réglés."""
    idx, counts = _index(model, logs, DRAW_EVENTS, block_ts)
    prize_window = model.c["PRIZE_WINDOW"]
    if not idx:
        return {"état": "AUCUN_TIRAGE_CONNU",
                "explication": "aucun `DrawOpened` sur la plage examinée — absence de données, pas "
                               "absence de problème.",
                "tirages_énumérés": 0, "alertes": [], "compteurs": counts}
    alertes = []
    for wid in sorted(idx):
        rec = idx[wid]
        if "DrawOpened" not in rec:
            continue
        opened_ts = min(x["ts"] for x in rec["DrawOpened"])
        if "DrawSettled" in rec or "PrizeClaimed" in rec or "PrizeReturned" in rec:
            continue
        age_j = (now_ts - opened_ts) / 86400.0
        if age_j >= alert_days:
            rendu_le = opened_ts + prize_window
            alertes.append({
                "gravité": "P1",
                "weekId": str(wid),
                "ouvert_le_ts": opened_ts,
                "âge_jours": round(age_j, 2),
                "rendu_au_safe_à_partir_de_ts": rendu_le,
                "jours_avant_retour": round((rendu_le - now_ts) / 86400.0, 2),
                "conséquence": "au 30e jour, `returnPrize` rend la dotation au Safe SANS GAGNANT. "
                               "`settleDraw` est ouvert à tous : n'importe qui peut encore sauver ce "
                               "tirage.",
            })
    return {"état": "COUVERTURE_OK", "tirages_énumérés": len(idx),
            "tirages_non_réglés": sum(1 for w in idx.values()
                                      if "DrawOpened" in w and "DrawSettled" not in w),
            "alertes": alertes, "compteurs": counts}


# ---------------------------------------------------------------------- journal des racines

class RootJournal:
    """Journal APPEND-ONLY des `WeekPosted` / `DrawOpened` vus. Deux racines pour un même `weekId` = P0.

    On garde `blockHash` : une racine qui réapparaît après réorganisation dans un bloc DIFFÉRENT avec
    la MÊME racine est un cas normal ; avec une AUTRE racine, c'est une tentative.
    """

    def __init__(self, state_dir, name="racines.json"):
        self.path = os.path.join(state_dir, name)
        self.data = {"WeekPosted": {}, "DrawOpened": {}}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        for k in ("WeekPosted", "DrawOpened"):
            self.data.setdefault(k, {})

    def observe(self, model, logs, block_ts):
        """Rend la liste des P0 détectés. N'écrase JAMAIS : le journal est en ajout seul."""
        abi = model.abi
        wanted = {abi.topic0("WeekPosted").lower(): ("WeekPosted", "root"),
                  abi.topic0("DrawOpened").lower(): ("DrawOpened", "weightsRoot")}
        p0 = []
        n_vus = 0
        for lg in logs:
            m = wanted.get(lg["topics"][0].lower())
            if m is None:
                continue
            name, field = m
            ev = decode_event(abi, name, lg)
            n_vus += 1
            wid = str(ev["weekId"])
            racine = ev[field]
            bn = int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"]
            entry = {"racine": racine, "bloc": bn, "blockHash": lg.get("blockHash"),
                     "transactionHash": lg.get("transactionHash"), "ts": block_ts(bn)}
            hist = self.data[name].setdefault(wid, [])
            if any(h["racine"] == racine and h.get("transactionHash") == entry["transactionHash"]
                   for h in hist):
                continue
            racines = {h["racine"] for h in hist}
            if racines and racine not in racines:
                p0.append({
                    "gravité": "P0", "événement": name, "weekId": wid,
                    "racine_déjà_vue": sorted(racines), "racine_nouvelle": racine,
                    "conséquence": f"`{'postWeek' if name == 'WeekPosted' else 'openDraw'}` n'est pas "
                                   f"rejouable : deux racines différentes pour un même weekId signifient "
                                   f"que deux transactions ont été soumises. Bloquer, décision humaine.",
                })
            hist.append(entry)
        return {"p0": p0, "journaux_vus": n_vus,
                "weekIds_suivis": len(self.data["WeekPosted"]) + len(self.data["DrawOpened"])}

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, ensure_ascii=False, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        return self.path
