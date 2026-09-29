"""Différentiels REPRENABLES, par segments de blocs à bornes FIXES (dette du 2026-09-28).

Pourquoi ce module existe
-------------------------
Les deux différentiels relisaient d'un seul tenant : le COMPLET tout depuis le déploiement, le QUOTIDIEN le
volume du jour plus un recouvrement de 200 000 blocs. Mesuré le 2026-09-29 (`mesures/segments-2026-09-29.json`) :
99 % du temps est dans `eth_getLogs` en série — 200 appels et ≈ 36 s par tranche de 20 200 blocs chez dRPC
(101 blocs par appel), 21 appels et ≈ 4,2 s chez le nœud officiel. Le complet croît donc de ≈ 13 min par JOUR
d'âge du contrat chez dRPC, et un job GitHub est tué à 36 min : sans reprise, `b` perdait ses différentiels et
`a` son complet avec l'âge, sans qu'aucune panne ne soit en cause.

Le modèle
---------
- Grille FIXE ancrée au bloc de déploiement : segment k = [dép + k·T, dép + (k+1)·T − 1], T = `TAILLE_SEGMENT`.
  La taille est inscrite dans l'état ; une autre taille rend l'état inutilisable (nommé, repris depuis zéro).
- Un POINT DE REPRISE par segment vérifié, écrit atomiquement APRÈS sa vérification (KE#112) : bornes, hash du
  bloc de fin lu chez le fournisseur de RÉFÉRENCE (l'état : c'est lui qui borne, KE#130/#152), empreinte et
  cardinal du résultat. L'exécution suivante reprend au premier segment non vérifié : une coupure à N'IMPORTE
  quelle frontière ne perd que le segment en cours.
- Un segment vérifié n'est JAMAIS relu, sauf s'il est INVALIDÉ, et toute invalidation vaut EN AVAL :
    (i)  le contenu du cache sur ses bornes n'a plus l'empreinte vérifiée (cache re-figé, rejeté, reconstruit) —
         zéro appel, contrôlé pour CHAQUE point ;
    (ii) le hash de la borne du dernier point, relu chez le fournisseur de référence, ne concorde plus
         (réorganisation, chaîne rejouée à la même identité — KE#132 —, finalité qui recule) : on recule point
         par point jusqu'à un hash qui concorde. Un hash qui concorde prouve toute l'ascendance (chaînage).
- Un segment CONTREDIT (cache ≠ chaîne) n'est jamais inscrit : le point n'est pas écrit, l'état persiste sans
  lui, et le rapport dit DIVERGENT (KE#151 : ce qui est contredit est écarté AVANT toute persistance).
- Liaison des journaux à la chaîne vérifiée (KE#152) : la relecture compare TOUT le journal canonique, `blockHash`
  compris, au cache — dont chaque `blockHash` a été confronté au fournisseur de référence au figeage. L'égalité
  lie donc la relecture à la référence ; et le fournisseur des journaux doit avoir ATTEINT la fin du segment
  (sinon une plage qu'il n'a pas encore servie se lirait vide).
- Budget : `échéance` (horodatage absolu). Avant chaque segment, on s'arrête si `maintenant + durée du plus long
  segment observé` la dépasse : arrêt PROPRE, rapport « PARTIEL, N segments sur M », couverture exacte (KE#111).
  JAMAIS « IDENTIQUE » tant que la couverture n'égale pas EXACTEMENT [déploiement, finalized] (KE#121).
- Progression POSITIVE exigée (KE#131/#157) : une exécution partielle qui ne vérifie rien est une ERREUR ; un
  retard de couverture qui ne se RÉSORBE pas (retard ≥ celui de l'exécution partielle précédente, ou couverture
  incomplète depuis plus d'une période) est un refus nommé que la surveillance consomme.

Les deux portées
----------------
- QUOTIDIENNE : campagne PERMANENTE. Chaque bloc figé est vérifié une fois ; seul le neuf est lu. Elle peut
  ADOPTER les points que le tour complet a déjà vérifiés au-delà de sa frontière (même grille, mêmes contrôles
  (i) et (ii) appliqués ensuite) : sans cela, le premier quotidien après un amorçage relirait tout.
- COMPLÈTE : par TOURS. Un tour relit tout depuis le déploiement, sur autant d'exécutions qu'il faut ; il en
  commence un nouveau quand le précédent est terminé ET que sa période (`tour_s`) est échue. Entre deux tours, le
  tour terminé est ÉTENDU jusqu'au `finalized` courant (seul le neuf est lu, après les contrôles (i) et (ii)) :
  un résultat `ok` veut donc toujours dire « couverture COMPLÈTE jusqu'à `finalized` lu sur la chaîne » (format
  imposé par le coordinateur le 2026-09-29). L'amorçage (preuve D) poursuit le tour sans le réinitialiser.

Couverture publiée (format IMPOSÉ, battement de la tâche et `health.json`) :
  {"bloc_debut", "bloc_fin_cible", "bloc_fin_verifie", "segments_verifies", "segments_total", "complet",
   "motif_partiel"} avec l'invariant complet == (bloc_fin_verifie == bloc_fin_cible and segments_verifies ==
  segments_total), recoupé avec le contrôle d'égalité exacte `_couvre_exactement` (un désaccord est une ERREUR).
"""
import bisect
import fcntl
import json
import math
import os
import time

from .journaux import (LecteurJournaux, RepriseError, _bn, _canon, _ecrire_atomique, _li, _verifier_couverture,
                       empreinte_journaux)
from .rpc import EcheanceDepassee

FORMAT = 1
# 20 200 blocs = 200 appels chez dRPC (101 blocs par appel) ≈ 36 s, 21 appels chez le nœud officiel ≈ 4,2 s
# (mesures/segments-2026-09-29.json). Assez petit pour qu'un arrêt au budget perde peu, assez grand pour que
# le point de reprise (1 lecture de bloc + 1 écriture) reste < 1 % du coût.
TAILLE_SEGMENT = 20_200
# Au-delà, les deux points COMPLETS les plus anciens sont fusionnés : l'état ne grossit pas avec l'âge.
MAX_POINTS = 64
HISTORIQUE = 20
# Estimation de la durée du PROCHAIN segment (décision « démarrer ou s'arrêter avant l'échéance ») : max des
# FENETRE_DUREES dernières durées observées — jamais un maximum historique sans oubli, qu'une seule valeur
# aberrante (relances 408) rendrait supérieur au budget POUR TOUJOURS (revue 2026-09-29, P0-1). Rien d'observé :
# PRIOR_SEGMENT_S = 2 × 36,4 s (dRPC, mesures/segments-2026-09-29.json). Et une exécution qui n'a encore rien
# vérifié plafonne son estimation au prior : elle tente TOUJOURS au moins un segment si le nominal tient,
# l'échéance DURE ci-dessous bornant le segment en vol.
FENETRE_DUREES = 10
PRIOR_SEGMENT_S = 72.8
# Échéance DURE du segment en vol : échéance + MARGE_DURE_S. Au-delà, la lecture est ABANDONNÉE entre deux
# tranches et le segment n'est pas inscrit. 120 s < 420 s de marge du job de `b` (36 min − 1 740 s), le reste
# couvrant une tranche en vol, le jugement et la publication.
MARGE_DURE_S = 120.0
PORTEES = {"quotidienne": "differentiel-quotidien.json", "complète": "differentiel-complet.json"}
ETATS = ("IDENTIQUE", "PARTIEL", "DIVERGENT", "VACUE")


class SegmentsError(RepriseError):
    """Échec BRUYANT du différentiel segmenté (verrou, fournisseur en retard, état incohérent)."""


def chemin_etat(state_dir, portee):
    if portee not in PORTEES:
        raise SegmentsError(f"ARRÊT : portée « {portee} » inconnue, attendu {sorted(PORTEES)}.")
    return os.path.join(state_dir, PORTEES[portee])


def _neuf(identite, taille, portee, maintenant):
    return {"format": FORMAT, **identite, "taille": taille, "portée": portee,
            "tour": {"numéro": 1, "commencé_ts": int(maintenant), "terminé_ts": None},
            "points": [], "historique": [], "durée_max_segment_s": None, "partiel_depuis_ts": None}


CLE_PREUVES = "finalités_violées_non_rapportées"      # nom historique : « non ACQUITTÉES par un humain »


IDENTITE_PREUVE = ("bloc", "hash_vérifié", "hash_lu")


def empreinte_preuve(preuve):
    """sha256 de l'IDENTITÉ de la preuve — les FAITS seuls (bloc, hash vérifié, hash lu), jamais l'horodatage de
    détection ni un contexte variable : sinon une même violation, revue à chaque exécution, serait re-consignée
    sous une empreinte neuve (revue 2026-09-29 : 5 → 10 → 15 preuves pour 5 faits). C'est ce qu'un humain cite."""
    import hashlib
    corps = {k: (str(preuve.get(k)).lower() if k != "bloc" else preuve.get(k)) for k in IDENTITE_PREUVE}
    return hashlib.sha256(json.dumps(corps, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def _empreinte_ancienne(preuve):
    """Formule de la passe PRÉCÉDENTE (livrée en `a`) : toute la preuve sauf `empreinte`, horodatage compris."""
    import hashlib
    corps = {k: v for k, v in preuve.items() if k != "empreinte"}
    return hashlib.sha256(json.dumps(corps, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def migrer_preuves(preuves):
    """Preuves au format d'une version précédente ⇒ empreinte des FAITS (revue 2026-09-29, P2) : sans champ
    `empreinte`, ou avec l'empreinte de l'ancienne formule (horodatage compris) qu'elle REPRODUIT. Une empreinte que
    ni l'une ni l'autre formule ne reproduit n'est PAS migrée : c'est une preuve ALTÉRÉE, et elle le reste."""
    out = []
    for e in preuves or []:
        e = dict(e)
        if e.get("empreinte") != empreinte_preuve(e):
            if "empreinte" not in e:
                e["empreinte"] = empreinte_preuve(e)
            elif e["empreinte"] == _empreinte_ancienne(e):
                e["empreinte_ancienne"] = e["empreinte"]
                e["empreinte"] = empreinte_preuve(e)
        out.append(e)
    return out


def _garder_preuves(ancien, neuf):
    """Un état REJETÉ (autre taille, identité…) ne fait JAMAIS disparaître une preuve de finalité (KE#160)."""
    if isinstance(ancien, dict) and ancien.get(CLE_PREUVES):
        neuf[CLE_PREUVES] = migrer_preuves(ancien[CLE_PREUVES])
    return neuf


def preuves_archivees(state_dir):
    """Empreintes déjà acquittées par un humain (`preuves-acquittees/<empreinte>.json`)."""
    d = os.path.join(state_dir, "preuves-acquittees")
    try:
        return {f[:-5] for f in os.listdir(d) if f.endswith(".json")}
    except OSError:
        return set()


def preuves_en_attente(state_dir):
    """Preuves NON acquittées des DEUX portées, lues sans RPC ni verrou (écritures atomiques) : ce que le chemin
    d'exception d'une tâche et l'amorçage consultent (revue 2026-09-29, P0-1 / P1-2)."""
    out = []
    for portee in PORTEES:
        try:
            with open(chemin_etat(state_dir, portee), "r", encoding="utf-8") as fh:
                out += migrer_preuves(json.load(fh).get(CLE_PREUVES))
        except (OSError, ValueError):
            pass
    return out


def _consigner_violation(doc, rapport, p, h, portee, maintenant, motif=None, state_dir=None):
    """La PREUVE est inscrite dans l'état, dans la MÊME écriture que la correction (KE#160), et n'est JAMAIS acquittée
    automatiquement (décision du coordinateur, 2026-09-29) : tant qu'elle est là, CHAQUE exécution re-publie
    `refus/differentiel_finalite_violee`. Seul un humain l'acquitte, par son EMPREINTE exacte :
    `python3 -B -m veilleur acquitter-finalite --preuve <empreinte>` (archivée, jamais effacée)."""
    motif = motif or f"le hash du bloc {p['à']} lu chez le fournisseur de référence ({h}) ≠ {p['hash_fin']}"
    preuve = {"bloc": p["à"], "hash_vérifié": (p["hash_fin"] or "").lower(), "hash_lu": (h or "").lower(),
              "ts": int(maintenant), "portée": portee, "motif": motif}
    preuve["empreinte"] = emp = empreinte_preuve(preuve)
    connue = next((e for e in doc.get(CLE_PREUVES) or [] if e.get("empreinte") == emp), None)
    if connue is not None:
        connue["vue_n"] = connue.get("vue_n", 1) + 1           # hors identité : ne change pas l'empreinte
        connue["dernière_vue_ts"] = int(maintenant)
    elif state_dir is None or emp not in preuves_archivees(state_dir):
        doc.setdefault(CLE_PREUVES, []).append(preuve)
    if rapport is not None:
        rapport["invalidations"].append({"contrôle": "hash_de_borne (point au contenu changé)", "motif": motif,
                                         "points_invalidés": 1, "depuis_bloc": p["de"], "finalité_violée": True})


def charger_etat(path, identite, taille, portee, maintenant):
    """Rend (état, motif de rejet | None). Un état d'une autre identité, d'une autre taille ou illisible n'est
    JAMAIS réutilisé — et le rejet est NOMMÉ dans le rapport, jamais un « repris depuis zéro » muet."""
    if not os.path.exists(path):
        return _neuf(identite, taille, portee, maintenant), None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        return _neuf(identite, taille, portee, maintenant), f"état illisible ({e}) : repris depuis zéro"
    ident = {k: doc.get(k) for k in identite}
    if doc.get("format") != FORMAT or ident != identite or doc.get("taille") != taille \
            or doc.get("portée") != portee:
        return _garder_preuves(doc, _neuf(identite, taille, portee, maintenant)), (
            f"état d'une autre identité, taille ou portée ({ident}, taille {doc.get('taille')}, portée "
            f"{doc.get('portée')} ≠ {identite}, {taille}, {portee}) : jamais réutilisé, repris depuis zéro")
    if doc.get(CLE_PREUVES):
        doc[CLE_PREUVES] = migrer_preuves(doc[CLE_PREUVES])
    return doc, None


class _Cache:
    """Les journaux figés, indexés par (bloc, index), pour extraire une plage sans rien relire."""

    def __init__(self, logs):
        self.logs = sorted(logs, key=lambda lg: (_bn(lg), _li(lg)))
        self.blocs = [_bn(lg) for lg in self.logs]

    def entre(self, de, a):
        return self.logs[bisect.bisect_left(self.blocs, de):bisect.bisect_right(self.blocs, a)]


def _fin_de_grille(dep, taille, bloc):
    return dep + ((bloc - dep) // taille + 1) * taille - 1


def verifier(client, settings, head, fin_bn, fin_hash, portee, *, echeance=None, tour_s=None,
             tolerance_s=0, periode_s=None, etendre=False, taille=TAILLE_SEGMENT, horloge=time.time,
             nouveau_tour=False):
    """Un différentiel segmenté. Rend le rapport (`état` ∈ ETATS, `couverture`, `segments_cette_exécution`…).

    `head`, `fin_bn`, `fin_hash` sont LUS SUR LA CHAÎNE par l'appelant : la borne de couverture est `finalized`,
    jamais ce que le cache ou l'état annoncent (KE#130). `echeance` : horodatage absolu d'arrêt propre.
    `tour_s` / `tolerance_s` : période du tour COMPLET (et marge de déclenchement) ; `periode_s` : période de la
    tâche, borne du « retard non résorbé » de la portée quotidienne. `etendre` : amorçage — le tour n'est jamais
    réinitialisé, il est poursuivi jusqu'à `finalized`. `nouveau_tour` (à la main) : commencer un tour neuf même si
    le précédent n'est pas échu.
    """
    if portee not in PORTEES:
        raise SegmentsError(f"ARRÊT : portée « {portee} » inconnue.")
    if taille < 1:
        raise SegmentsError(f"ARRÊT : taille de segment {taille} hors domaine.")
    t0 = horloge()
    a0 = client.stats.get("calls", 0)
    inc = LecteurJournaux(client, settings, mode="incrémental")
    # Le cache est mis à jour jusqu'à `finalized` (point de reprise du CACHE vérifié par hash) : c'est lui que
    # le différentiel confronte à la chaîne.
    # Le figeage est borné par la MÊME échéance (revue P1-3) : un cache écarté puis reconstruit sur un contrat âgé
    # ne doit pas faire tuer le job ; chaque pas figé est persisté, la couverture le dira.
    # l'échéance est dans l'horloge de l'appelant ; le lecteur de cache compte en temps réel
    ech_reel = None if echeance is None else time.time() + (echeance - horloge())
    _, _, r_inc = inc.lire(head, fin_bn, fin_hash, echeance=ech_reel, lire_queue=False)
    appels_cache = client.stats.get("calls", 0) - a0
    _, segs, probleme = inc.magasin.charger()
    interrompu = r_inc.get("figeage_interrompu")
    if not segs and interrompu is None:
        raise SegmentsError("ARRÊT : aucun cache figé — rien à vérifier. Amorcer d'abord (README). "
                            + (f"Cache rejeté : {probleme}" if probleme else ""))
    ident = inc.identite
    dep = ident["deploy_block"]
    cible = max(dep - 1, fin_bn)                          # borne tirée de la CHAÎNE
    fige = segs[-1][0]["à"] if segs else dep - 1
    verifiable = min(cible, fige)
    cache = _Cache([lg for _, lgs, _ in segs for lg in lgs])

    path = chemin_etat(settings.state_dir, portee)
    os.makedirs(settings.state_dir, exist_ok=True)
    verrou = open(path + ".verrou", "a+")
    try:
        try:
            fcntl.flock(verrou.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SegmentsError(f"ARRÊT : un différentiel « {portee} » est DÉJÀ en cours sur cet état "
                                f"({path}) : deux écrivains se disputeraient le point de reprise.") from None
        # Échéance DURE posée sur le CLIENT (délai de chaque appel ≤ ce qui reste, aucune relance au-delà) : elle
        # borne aussi l'appel EN VOL, la lecture des bornes et l'arbitrage — pas seulement l'intervalle entre deux
        # tranches (contre-revue 2026-09-29, P1-B).
        if echeance is not None:
            client.poser_echeance_dure(time.time() + (echeance - horloge()) + MARGE_DURE_S)
        try:
            return _verifier(client, settings, portee, path, ident, dep, cible, verifiable, fige, cache, fin_bn,
                             fin_hash, head, echeance, tour_s, tolerance_s, periode_s, etendre, taille, horloge,
                             t0, a0, appels_cache, r_inc, probleme, nouveau_tour)
        finally:
            if echeance is not None:
                client.poser_echeance_dure(None)
    finally:
        fcntl.flock(verrou.fileno(), fcntl.LOCK_UN)
        verrou.close()


def _verifier(client, settings, portee, path, ident, dep, cible, verifiable, fige, cache, fin_bn, fin_hash,
              head, echeance, tour_s, tolerance_s, periode_s, etendre, taille, horloge, t0, a0, appels_cache,
              r_inc, probleme_cache, nouveau_tour):
    maintenant = horloge()
    budget_s = None if echeance is None else echeance - t0
    doc, rejet = charger_etat(path, ident, taille, portee, maintenant)
    rapport = {"portée": portee, "borne": {"tête": head, "finalized": fin_bn, "cible": cible,
                                           "source": "tête et finalized lus sur la chaîne (KE#130)"},
               "taille_segment": taille, "état_rejeté": rejet, "cache_rejeté": probleme_cache,
               "périmètre": ("cache figé confronté à une RELECTURE du fournisseur des journaux (dRPC pour b) ; le "
                             "fournisseur de référence n'est consulté que sur désaccord. IDENTIQUE prouve « cache == "
                             "relecture », pas l'absence d'un mensonge CONSTANT du fournisseur des journaux (KE#127)."),
               "cache_figé_jusqu_à": fige, "invalidations": [], "adoptés": 0,
               "appels_mise_à_jour_du_cache": appels_cache,
               "lecture_du_cache": {k: r_inc.get(k) for k in ("reprise_depuis", "divergence", "cache_rejeté",
                                                               "figeage_interrompu")}}
    progres_cache = ((r_inc.get("écriture") or {}).get("segments_écrits_cette_passe") or 0) > 0

    # ------------------------------------------------------------ le tour (portée complète)
    # Un tour échu recommence ici (points remis à zéro) ; sinon le tour — terminé ou non — est poursuivi / ÉTENDU
    # jusqu'au `finalized` courant, APRÈS les contrôles (i) et (ii) (revue 2026-09-29, P1-2 : aucun raccourci
    # « à jour » ne rend `ok` sans eux).
    tour = doc["tour"]
    if portee == "complète" and not etendre and tour["terminé_ts"] is not None:
        du = nouveau_tour or tour_s is None or maintenant - tour["commencé_ts"] >= tour_s - tolerance_s
        if du:
            doc["tour"] = tour = {"numéro": tour["numéro"] + 1, "commencé_ts": int(maintenant),
                                  "terminé_ts": None}
            doc["points"] = []
            doc["partiel_depuis_ts"] = None
            rapport["nouveau_tour"] = tour["numéro"]
    points = doc["points"]

    # ------------------------------------------------------------ adoption (portée quotidienne)
    if portee == "quotidienne":
        rapport["adoptés"] = _adopter(points, settings.state_dir, ident, taille, dep, maintenant)

    # ------------------------------------------------------------ (i) contenu du cache == contenu vérifié
    for i, p in enumerate(points):
        motif = None
        if p["à"] > fige:
            motif = f"le cache ne couvre plus le point [{p['de']}, {p['à']}] (figé jusqu'à {fige})"
        else:
            e, n = empreinte_journaux(cache.entre(p["de"], p["à"]))
            if (e, n) != (p["empreinte"], p["journaux"]):
                motif = (f"le contenu du cache sur [{p['de']}, {p['à']}] a changé depuis sa vérification "
                         f"({n} journaux, empreinte {e[:12]}… ≠ {p['journaux']}, {p['empreinte'][:12]}…)")
        if motif:
            rapport["invalidations"].append({"contrôle": "contenu", "motif": motif,
                                             "points_invalidés": len(points) - i, "depuis_bloc": p["de"]})
            # Un contenu changé peut CACHER une finalité violée (cache re-figé sur une chaîne rejouée : blockHash
            # neufs) : la borne de CHAQUE point retiré est confrontée à la référence AVANT de le retirer — sinon (ii)
            # ne voit plus que les points antérieurs, intacts, et la violation passe pour un simple cache changé.
            for q in points[i:]:
                if q["à"] > cible:
                    continue
                hq = fin_hash if q["à"] == fin_bn else client.block(q["à"])["hash"]
                if (hq or "").lower() != (q["hash_fin"] or "").lower():
                    _consigner_violation(doc, rapport, q, hq, portee, maintenant, state_dir=settings.state_dir)
            del points[i:]
            break

    # ------------------------------------------------------------ (ii) hash de la borne, fournisseur de référence
    while points:
        p = points[-1]
        if p["à"] > cible:
            # peut être bénin (nœud d'état en retard derrière une URL publique, KE#133) : invalidé, pas accusé
            viole = False
            motif = (f"la borne {p['à']} est au-delà de finalized {fin_bn} : chaîne réinitialisée, finalité qui "
                     f"recule, ou nœud de référence en retard")
        else:
            h = fin_hash if p["à"] == fin_bn else client.block(p["à"])["hash"]
            if (h or "").lower() == (p["hash_fin"] or "").lower():
                break
            # un hash DIFFÉRENT sous `finalized` : finalité violée ou chaîne rejouée (KE#132) — un incident en soi,
            # jamais absorbé dans un `ok` même si la relecture redevient IDENTIQUE (revue P1-5, KE#105)
            viole = True
            motif = f"le hash du bloc {p['à']} lu chez le fournisseur de référence ({h}) ≠ {p['hash_fin']}"
        rapport["invalidations"].append({"contrôle": "hash_de_borne", "motif": motif, "points_invalidés": 1,
                                         "depuis_bloc": p["de"], "finalité_violée": viole})
        if viole:
            _consigner_violation(doc, None, p, h, portee, maintenant, motif, state_dir=settings.state_dir)
        points.pop()
    rapport["finalités_violées"] = list(doc.get("finalités_violées_non_rapportées") or [])
    if rapport["invalidations"] or rejet or rapport["adoptés"] or rapport.get("nouveau_tour") \
            or not os.path.exists(path):
        _ecrire_atomique(path, doc)            # invalidation, tour neuf, adoption : persistés AVANT toute relecture

    # ------------------------------------------------------------ vérification, segment par segment
    faits = []
    arret = None
    frontiere = points[-1]["à"] + 1 if points else dep
    while frontiere <= verifiable:
        fin_fixe = _fin_de_grille(dep, taille, frontiere)
        a = min(fin_fixe, verifiable)
        if echeance is not None:
            fen = doc.get("durées_segments") or []       # la FENÊTRE est tenue à l'écriture (une seule garde)
            vues = [f["durée_s"] for f in faits] + fen
            estim = max(vues) if vues else PRIOR_SEGMENT_S
            if not faits:
                estim = min(estim, PRIOR_SEGMENT_S)        # jamais d'affamement persistant (P0-1)
            if horloge() + estim > echeance:
                arret = (f"budget : arrêt propre avant le segment [{frontiere}, {a}] — il reste "
                         f"{max(0, round(echeance - horloge(), 1))} s, le plus long segment observé en prend "
                         f"{round(estim, 1)}")
                break
        ts, c0 = horloge(), client.stats.get("calls", 0)
        try:
            frais = _relire(client, settings, ident, frontiere, a, echeance, horloge)
        except EcheanceDepassee as e:
            arret = f"segment [{frontiere}, {a}] ABANDONNÉ en vol, NON inscrit : {e}"
            break
        du_cache = cache.entre(frontiere, a)
        ef, nf = empreinte_journaux(frais)
        ec, nc = empreinte_journaux(du_cache)
        if (ef, nf) != (ec, nc):
            # KE#133/#156 : un nœud en retard derrière l'URL publique rend une tranche vide. On reprend
            # l'INSTANTANÉ ENTIER (tête du fournisseur relue, segment relu en entier), une fois.
            try:
                frais = _relire(client, settings, ident, frontiere, a, echeance, horloge)
            except EcheanceDepassee as e:
                arret = f"segment [{frontiere}, {a}] ABANDONNÉ en vol pendant sa relecture, NON inscrit : {e}"
                break
            ef, nf = empreinte_journaux(frais)
        if (ef, nf) != (ec, nc):
            ca = {(x["blockNumber"], x["logIndex"]): x for x in map(_canon, du_cache)}
            ch = {(x["blockNumber"], x["logIndex"]): x for x in map(_canon, frais)}
            ecarts = set(ca) ^ set(ch) | {k for k in set(ca) & set(ch) if ca[k] != ch[k]}
            try:
                arbitre = _arbitrer(client, settings, ident, ca, ecarts)
            except EcheanceDepassee as e:
                arret = f"segment [{frontiere}, {a}] ABANDONNÉ pendant son arbitrage, NON inscrit : {e}"
                break
            if arbitre == "référence_illisible":
                raise SegmentsError(
                    f"ARRÊT : sur [{frontiere}, {a}], le cache et le fournisseur des journaux divergent et la "
                    f"RÉFÉRENCE n'a pas pu relire les blocs en désaccord : indécidable, rien n'est conclu (le cache "
                    f"n'est ni contredit ni inscrit).")
            if arbitre == "cache":
                # la RÉFÉRENCE rend exactement le cache sur les blocs en désaccord : c'est le fournisseur des
                # journaux qui est incohérent — le cache n'est PAS contredit (ni inscrit, ni écarté)
                raise SegmentsError(
                    f"ARRÊT : sur [{frontiere}, {a}], le fournisseur des JOURNAUX rend autre chose que le cache, "
                    f"et la RÉFÉRENCE rend exactement le cache sur les {len({k[0] for k in ecarts})} bloc(s) en "
                    f"désaccord : fournisseur des journaux incohérent, cache NON contredit. Segment non inscrit.")
            doc["contredit"] = {"de": frontiere, "à": a, "ts": int(horloge()), "arbitrage": arbitre}
            _historiser(doc, horloge(), cible, points, len(faits), "DIVERGENT")
            _ecrire_atomique(path, doc)        # SANS le segment contredit (KE#151)
            rapport.update({
                "état": "DIVERGENT", "segment": [frontiere, a], "arbitrage_référence": arbitre,
                "tour": dict(doc["tour"]),
                "détail": {"absents_du_cache": sorted(set(ch) - set(ca))[:10],
                           "en_trop_dans_le_cache": sorted(set(ca) - set(ch))[:10],
                           "contenus_différents": sorted(k for k in set(ca) & set(ch) if ca[k] != ch[k])[:10]},
                "motif": (f"le cache figé NE rend PAS les journaux de la chaîne sur [{frontiere}, {a}] (relu deux "
                          f"fois ; arbitrage de la référence : {arbitre}) : P0. Ce segment n'est PAS inscrit ; ne "
                          f"plus se fier au cache, l'écarter et repartir de zéro."),
                "invalidations": rapport["invalidations"],
                "segments_cette_exécution": faits,
                **_publier_couverture(doc, dep, cible, taille, horloge(), budget_s, periode_s, faits, "DIVERGENT",
                                      f"segment [{frontiere}, {a}] contredit"),
                "appels_rpc": client.stats.get("calls", 0) - a0, "durée_s": round(horloge() - t0, 3)})
            return rapport
        try:
            h = fin_hash if a == fin_bn else client.block(a)["hash"]
        except EcheanceDepassee as e:
            arret = f"segment [{frontiere}, {a}] ABANDONNÉ à la lecture de sa borne, NON inscrit : {e}"
            break
        prec = points[-1] if points else None
        if prec is not None and prec["à"] + 1 == frontiere and prec["à"] < _fin_de_grille(dep, taille, prec["de"]):
            # le point précédent était PARTIEL (queue d'un segment) : on l'ÉTEND, sans relire sa partie vérifiée
            e, n = empreinte_journaux(cache.entre(prec["de"], a))
            prec.update({"à": a, "hash_fin": h, "empreinte": e, "journaux": n, "vérifié_ts": int(horloge())})
        else:
            points.append({"de": frontiere, "à": a, "hash_fin": h, "empreinte": ec, "journaux": nc,
                           "segments": 1, "vérifié_ts": int(horloge())})
        _compacter(points, dep, taille, cache)
        d = round(horloge() - ts, 3)
        faits.append({"de": frontiere, "à": a, "journaux": nc, "appels": client.stats.get("calls", 0) - c0,
                      "durée_s": d})
        doc["durées_segments"] = ((doc.get("durées_segments") or []) + [d])[-FENETRE_DUREES:]
        doc["durée_max_segment_s"] = max(doc["durées_segments"])     # publié ; la décision lit la FENÊTRE
        _ecrire_atomique(path, doc)            # point de reprise DURABLE à chaque frontière
        frontiere = a + 1

    # ------------------------------------------------------------ bilan : couverture en ÉGALITÉ exacte
    maintenant = horloge()
    complet = _couvre_exactement(points, dep, cible)
    n_total = sum(p["journaux"] for p in points)
    if complet and n_total == 0:
        etat = "VACUE"
        motif = ("ZÉRO journal sur toute la couverture : l'égalité de deux listes vides ne prouve rien (KE#121) — "
                 "le journal du constructeur manque, la lecture ne voit pas le contrat.")
    elif complet:
        etat, motif = "IDENTIQUE", None
    else:
        etat = "PARTIEL"
        motif = arret or (f"cache figé jusqu'au bloc {fige}, finalized {fin_bn} : le cache n'a pas atteint la "
                          f"borne de la chaîne" if fige < cible else "couverture incomplète")
    cv, _ = _couverture(doc, dep, cible, taille, maintenant, budget_s, periode_s, faits, etat)
    if cv["complet"] != complet:
        # deux calculs INDÉPENDANTS de la même propriété : leur désaccord est un défaut du code, jamais arbitré
        raise SegmentsError(f"ARRÊT : couverture incohérente — égalité exacte {complet}, format publié "
                            f"{cv['complet']} ({cv}).")
    code = None
    if etat == "PARTIEL":
        code, motif = _progression(doc, portee, points, cible, faits, maintenant, tour_s, tolerance_s, periode_s,
                                   etendre, motif, progres_cache)
        if doc.get("partiel_depuis_ts") is None:
            doc["partiel_depuis_ts"] = int(maintenant)
    else:
        doc["partiel_depuis_ts"] = None
        doc.pop("contredit", None)
        if etat == "IDENTIQUE" and portee == "complète" and doc["tour"]["terminé_ts"] is None:
            doc["tour"]["terminé_ts"] = int(maintenant)
    _historiser(doc, maintenant, cible, points, len(faits), etat)
    _ecrire_atomique(path, doc)
    rapport.update({"état": etat, "code": code, "motif": motif, "tour": dict(doc["tour"]),
                    "segments_cette_exécution": faits,
                    **_publier_couverture(doc, dep, cible, taille, maintenant, budget_s, periode_s, faits, etat, motif),
                    "appels_rpc": client.stats.get("calls", 0) - a0, "durée_s": round(maintenant - t0, 3)})
    return rapport


def _couvre_exactement(points, dep, cible):
    """Couverture en ÉGALITÉ exacte (KE#121) : points contigus depuis le déploiement, fin == cible, et la somme des
    longueurs == cible − dép + 1. Une couverture vide n'est jamais « complète » sauf chaîne sans bloc figé."""
    if cible < dep:
        return False
    if not points:
        return False
    try:
        total = _verifier_couverture([(p["de"], p["à"]) for p in points], dep, points[-1]["à"])
    except RepriseError:
        return False
    return points[-1]["à"] == cible and total == cible - dep + 1


def _progression(doc, portee, points, cible, faits, maintenant, tour_s, tolerance_s, periode_s, etendre, motif,
                 progres_cache=False):
    """PARTIEL n'est jamais vert. Trois codes, du plus grave au moins grave (KE#131/#157) :
    - `differentiel_sans_progression` : rien vérifié ET rien figé alors qu'il restait à faire — la tâche n'a pas
      fait son travail (une exécution qui a RE-FIGÉ le cache sans rien vérifier a progressé : c'est un partiel) ;
    - `differentiel_retard_non_resorbe` : le retard ne diminue pas d'une exécution partielle à l'autre, OU la
      couverture est incomplète depuis plus que sa borne (tour complet : `tour_s` ; quotidien : `periode_s`) ;
    - `differentiel_partiel` : progression positive, couverture pas encore complète."""
    retard = cible - (points[-1]["à"] if points else doc["deploy_block"] - 1)
    if not faits and not progres_cache:
        return "differentiel_sans_progression", f"AUCUN segment vérifié ni figé cette exécution : {motif}"
    if etendre:
        return "differentiel_partiel", motif
    hist = doc.get("historique") or []
    prec = hist[-1] if hist and hist[-1].get("état") == "PARTIEL" else None
    # jambe 1 : le retard de VÉRIFICATION n'a pas diminué alors qu'on a vérifié (la chaîne va plus vite)
    if faits and prec is not None and retard >= prec["retard_blocs"]:
        return "differentiel_retard_non_resorbe", (
            f"le retard de couverture ne se résorbe pas : {retard} blocs non vérifiés, {prec['retard_blocs']} à "
            f"l'exécution partielle précédente — la chaîne avance plus vite que la vérification. {motif}")
    if portee == "complète" and tour_s is not None:
        depuis, borne, quoi = doc["tour"]["commencé_ts"], tour_s + tolerance_s, "le tour complet"
    else:
        depuis = doc.get("partiel_depuis_ts")
        borne, quoi = (None if periode_s is None else periode_s + tolerance_s), "la couverture quotidienne"
    if depuis is not None and borne is not None and maintenant - depuis > borne:
        return "differentiel_retard_non_resorbe", (
            f"{quoi} est incomplète depuis {int(maintenant - depuis)} s, au-delà de sa borne de {int(borne)} s. "
            f"{motif}")
    return "differentiel_partiel", motif


def _historiser(doc, maintenant, cible, points, n_faits, etat):
    fin = points[-1]["à"] if points else None
    retard = cible - fin if fin is not None else cible - doc["deploy_block"] + 1
    doc["historique"] = (doc.get("historique") or [])[-(HISTORIQUE - 1):] + [
        {"ts": int(maintenant), "état": etat, "retard_blocs": int(retard), "segments_vérifiés": n_faits,
         "couvert_jusqu_à": fin}]


def _couverture(doc, dep, cible, taille, maintenant, budget_s, periode_s, faits, etat, motif=None):
    """Couverture au FORMAT IMPOSÉ (coordinateur, 2026-09-29), bornes tirées de la source (KE#130) : déploiement et
    `finalized` lu sur la chaîne. L'estimation (segments restants, échéance) est rendue À PART."""
    points = doc["points"]
    fin = points[-1]["à"] if points else dep - 1
    total_seg = 0 if cible < dep else (cible - dep) // taille + 1
    # Compté INDÉPENDAMMENT de `fin` (contre-revue P2-6) : segments de grille entièrement couverts par CHAQUE point
    # (un point commence toujours sur la grille), plus le segment de queue quand un point s'arrête sur la cible.
    faits_seg = 0
    for p in points:
        long_ = p["à"] - p["de"] + 1
        faits_seg += long_ // taille + (1 if long_ % taille and p["à"] == cible else 0)
    complet = (fin == cible and faits_seg == total_seg)
    cv = {"bloc_debut": dep, "bloc_fin_cible": cible, "bloc_fin_verifie": fin, "segments_verifies": faits_seg,
          "segments_total": total_seg, "complet": complet,
          "motif_partiel": None if complet else (motif or f"état {etat}")}
    restants = max(0, total_seg - faits_seg)
    moy = (sum(f["durée_s"] for f in faits) / len(faits)) if faits else doc.get("durée_max_segment_s")
    reste_s = None if moy is None else round(restants * moy, 1)
    est = {"segments_restants": restants, "retard_blocs": max(0, cible - fin),
           "journaux_couverts": sum(p["journaux"] for p in points), "tour": doc.get("tour"),
           "durée_restante_estimée_s": reste_s}
    if restants == 0:
        est["échéance_estimée_ts"] = int(maintenant)
    elif reste_s is not None:
        if budget_s is not None and periode_s:
            n = math.ceil(reste_s / max(1.0, budget_s))
            est["échéance_estimée_ts"] = int(maintenant + n * periode_s)
            est["échéance_hypothèse"] = (f"{n} exécution(s) de plus à la période déclarée ({periode_s} s), budget "
                                         f"≈ {int(budget_s)} s chacune, hors croissance de la chaîne")
        else:
            est["échéance_estimée_ts"] = int(maintenant + reste_s)
            est["échéance_hypothèse"] = "une exécution sans budget, hors croissance de la chaîne"
    else:
        est["échéance_estimée_ts"] = None
        est["échéance_hypothèse"] = "aucune durée de segment observée : non estimable"
    return cv, est


def _publier_couverture(doc, dep, cible, taille, maintenant, budget_s, periode_s, faits, etat, motif=None):
    cv, est = _couverture(doc, dep, cible, taille, maintenant, budget_s, periode_s, faits, etat, motif)
    return {"couverture": cv, "couverture_estimation": est}


def _compacter(points, dep, taille, cache):
    """Fusionne les deux points COMPLETS les plus anciens au-delà de MAX_POINTS (empreinte recalculée sur le cache
    déjà vérifié) : l'état ne grossit pas avec l'âge ; seule la finesse d'une invalidation très ancienne s'y perd."""
    # `q` n'est jamais le dernier point (MAX_POINTS ≥ 3) : c'est le seul qui puisse être partiel. Une garde
    # « q partiel » serait inatteignable, donc décorative (KE#129) — l'invariant est tenu par la condition de boucle.
    while len(points) > MAX_POINTS:
        p, q = points[0], points[1]
        e, n = empreinte_journaux(cache.entre(p["de"], q["à"]))
        points[0:2] = [{"de": p["de"], "à": q["à"], "hash_fin": q["hash_fin"], "empreinte": e, "journaux": n,
                        "segments": p.get("segments", 1) + q.get("segments", 1), "vérifié_ts": q["vérifié_ts"]}]


def _adopter(points, state_dir, ident, taille, dep, maintenant):
    """Portée quotidienne : reprend, au-delà de sa frontière, les points que le tour COMPLET a vérifiés (même
    identité, même grille). Ils subissent ENSUITE les mêmes contrôles (i) et (ii) que les siens."""
    autre, rejet = charger_etat(chemin_etat(state_dir, "complète"), ident, taille, "complète", maintenant)
    if rejet or not autre["points"]:
        return 0
    frontiere = points[-1]["à"] + 1 if points else dep
    if points and points[-1]["à"] != _fin_de_grille(dep, taille, points[-1]["de"]):
        return 0                                 # notre dernier point est partiel : pas de raccord propre
    # (Pas de garde « ne pas adopter un point vicié » : l'empreinte des FAITS dédoublonne et l'archive empêche une
    # preuve acquittée de revenir — une seconde garde serait indémontrable, KE#139.)
    n = 0
    for p in autre["points"]:
        if p["de"] == frontiere:
            points.append(dict(p))
            frontiere = p["à"] + 1
            n += 1
    return n


def _relire(client, settings, ident, de, a, echeance, horloge):
    """Relecture d'UN segment chez le fournisseur des journaux : sa tête doit avoir ATTEINT la fin du segment
    (KE#152), la couverture doit être exacte, chaque journal à la bonne adresse et dans la plage. L'échéance DURE
    est celle du CLIENT (`poser_echeance_dure`) : un appel qui la franchirait lève `EcheanceDepassee`, rien n'est
    rendu."""
    # tête du fournisseur des JOURNAUX (un seul fournisseur : la même URL, derrière laquelle un nœud peut être en
    # retard, KE#133 — la garde vaut aussi pour l'instance `a`)
    tete_j = int(client.must_journaux("eth_blockNumber", []) if hasattr(client, "must_journaux")
                 else client.must("eth_blockNumber", []), 16)
    if tete_j < a:
        raise SegmentsError(
            f"ARRÊT : le fournisseur des JOURNAUX annonce la tête {tete_j}, en RETARD sur la fin du segment "
            f"[{de}, {a}] : sa plage se lirait vide et contredirait un cache juste. Rien n'est conclu ; les "
            f"segments vérifiés avant restent acquis.")
    frais, couv = client.get_logs_chunked(settings.rewards, None, de, a)
    _verifier_couverture(couv, de, a)
    for lg in frais:
        if (lg.get("address") or "").lower() != ident["rewards"] or not de <= _bn(lg) <= a:
            raise SegmentsError(f"ARRÊT : journal hors adresse ou hors plage servi pour [{de}, {a}] "
                                f"({lg.get('address')}, bloc {_bn(lg)}).")
    return frais


def _arbitrer(client, settings, ident, ca, ecarts):
    """Désaccord persistant cache ↔ fournisseur des journaux : la RÉFÉRENCE (fournisseur de l'état) relit les
    SEULS blocs en désaccord. Rend « cache » si elle rend exactement le cache sur ces blocs (le fournisseur des
    journaux est incohérent), « chaîne » sinon (le cache est contredit), « sans_arbitre » quand il n'y a qu'un
    fournisseur (instance `a` : la relecture EST la référence)."""
    etat = getattr(client, "etat", None)
    if etat is None:
        return "sans_arbitre"
    blocs = sorted({k[0] for k in ecarts})
    for bn in blocs:
        r = etat.get_logs(ident["rewards"], None, bn, bn)
        if r["kind"] != "ok":
            return "référence_illisible"
        ref = {(x["blockNumber"], x["logIndex"]): x for x in map(_canon, r["result"])}
        cache_bloc = {k: v for k, v in ca.items() if k[0] == bn}
        if ref != cache_bloc:
            return "chaîne"
    return "cache"


def acquitter_finalite(state_dir, empreinte, par):
    """Acquittement HUMAIN d'une preuve de finalité violée, par son EMPREINTE exacte (64 hexa). La même preuve peut vivre
    dans les DEUX portées (la quotidienne adopte les points de la complète) : TOUTES sont balayées (contre-revue,
    P1-A). Introuvable partout ⇒ `SegmentsError`, rien touché. Trouvée : ARCHIVÉE une fois dans
    `<état>/preuves-acquittees/<empreinte>.json` (qui, quand) et journalisée (`journal.jsonl`), PUIS retirée de chaque
    état qui la porte — jamais effacée sans trace. Rend l'archive, avec la liste des portées nettoyées."""
    import re
    if not re.fullmatch(r"[0-9a-f]{64}", empreinte or ""):
        raise SegmentsError(f"ARRÊT : empreinte « {empreinte} » : 64 caractères hexadécimaux attendus (la preuve se "
                            f"cite EXACTEMENT, jamais par préfixe).")
    dossier = os.path.join(state_dir, "preuves-acquittees")
    cible_arch = os.path.join(dossier, f"{empreinte}.json")
    archive = None
    reprise = os.path.exists(cible_arch)      # mort entre l'archive et le retrait : le « quand » d'origine reste
    nettoyees = []
    for portee in PORTEES:
        path = chemin_etat(state_dir, portee)
        if not os.path.exists(path):
            continue
        verrou = open(path + ".verrou", "a+")
        try:
            try:
                fcntl.flock(verrou.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise SegmentsError(f"ARRÊT : un différentiel « {portee} » tient le verrou de {path} : réessayer "
                                    f"quand il est fini (rien de plus n'est touché).") from None
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            preuves = migrer_preuves(doc.get(CLE_PREUVES))
            if any(e.get("empreinte") == empreinte and empreinte_preuve(e) != empreinte for e in preuves):
                raise SegmentsError(f"ARRÊT : une preuve porte l'empreinte {empreinte} mais ses FAITS ne la "
                                    f"produisent pas : preuve ALTÉRÉE, rien n'est acquitté (examiner {path}).")
            trouvees = [e for e in preuves if e.get("empreinte") == empreinte and empreinte_preuve(e) == empreinte]
            if not trouvees:
                continue
            if archive is None:
                archive = {"preuve": trouvees[0], "acquittée_par": par,
                           "acquittée_le": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                os.makedirs(dossier, exist_ok=True)
                if not reprise:
                    _ecrire_atomique(cible_arch, archive)      # archive D'ABORD
            reste = [e for e in preuves if e.get("empreinte") != empreinte]
            if reste:
                doc[CLE_PREUVES] = reste
            else:
                doc.pop(CLE_PREUVES, None)
            _ecrire_atomique(path, doc)                                                 # retirée ENSUITE
            nettoyees.append(portee)
        finally:
            fcntl.flock(verrou.fileno(), fcntl.LOCK_UN)
            verrou.close()
    if archive is None:
        raise SegmentsError(f"ARRÊT : aucune preuve de finalité violée d'empreinte {empreinte} dans {state_dir} : "
                            f"rien n'est acquitté (vérifier `finalités_violées` dans derniere-differentiel-*.json).")
    archive = dict(archive, portées=nettoyees)
    with open(os.path.join(dossier, "journal.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(dict(archive, reprise=reprise), ensure_ascii=False, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return archive
