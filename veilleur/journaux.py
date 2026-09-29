"""Lecture INCRÉMENTALE des journaux de `SpindexRewards`, avec un point de reprise VÉRIFIÉ contre la chaîne.

Pourquoi ce module existe
-------------------------
Jusqu'ici chaque passe relisait TOUS les journaux depuis le bloc de déploiement, par tranches de 1 000
blocs : à 9,9 blocs/s, ~25 700 appels par relecture au bout d'un mois, et la surveillance en faisait
jusqu'à trois. Le coût croissait sans borne, alors que la table de tirage doit être vérifiée dans les
5 minutes. Un veilleur dont la passe dure des heures est un veilleur muet par construction.

Ce qui est figé, et ce qui ne l'est JAMAIS
------------------------------------------
- On ne fige que jusqu'au bloc `finalized` LU PENDANT LA PASSE (~12 000 blocs derrière la tête sur la
  4663). Au-delà, tout est RELU à chaque passe : une réorganisation y est normale, et un journal figé
  dans une zone réorganisable resterait faux pour toujours.
- Le point de reprise porte le HASH du dernier bloc figé. À chaque passe, ce hash est RELU sur la
  chaîne. S'il a changé (chaîne réinitialisée à la même identité — KE#132 —, nœud qui ment, ou
  finalité violée), on recule segment par segment jusqu'à un hash qui concorde, ou jusqu'au bloc de
  déploiement, et on le DIT dans le rapport. Un hash qui concorde prouve toute l'ascendance : c'est la
  propriété de chaînage des blocs, et c'est pour cela qu'un seul appel suffit à vérifier le cache.
- La borne de COUVERTURE vient de la CHAÎNE (tête et `finalized` lus dans la passe), jamais du point de
  reprise (KE#130) : la réunion [cache] + [neuf figé] + [queue relue] doit recouvrir EXACTEMENT
  [bloc de déploiement, tête], sinon la passe s'arrête.

La reconstruction complète depuis zéro reste la RÉFÉRENCE
---------------------------------------------------------
Le mode `complet` ne lit aucun cache : c'est ce que fait le vérificateur public, c'est la garantie
« reproductible par n'importe qui ». Le mode `incrémental` doit rendre EXACTEMENT les mêmes journaux, et
`segments.verifier()` le vérifie, segment par segment, contre une relecture de la chaîne (empreinte
canonique égale, cardinal non nul exigé sur la couverture — deux listes vides sont égales et ne prouvent
rien, KE#121).

Écritures (KE#112)
------------------
Segment puis curseur, chacun en `.tmp` + `fsync` + `os.replace`, puis `fsync` du dossier. Le curseur est
le point de validation : un segment écrit sans curseur est un orphelin, ignoré puis nettoyé. Deux
écrivains (le timer et une vérification lancée à la main) ne se bloquent pas : celui qui trouve le
curseur modifié depuis sa lecture CÈDE l'écriture — ses journaux en mémoire restent justes pour sa passe.
Aucune hypothèse de disque partagé entre instances : chaque instance a son propre dossier d'état.
"""
import fcntl
import hashlib
import json
import os
import time

FORMAT = 1
DOSSIER = "journaux"
CURSEUR = "curseur.json"
# Au-delà, les segments sont fusionnés en un seul : le curseur ne grossit pas sans fin (une passe
# toutes les 5 min = 288 segments par jour sinon).
MAX_SEGMENTS = 64
MODES = ("incrémental", "complet")
# Rattrapage : un segment figé tous les 200 000 blocs (~200 appels `eth_getLogs`, ~5,6 h de chaîne).
PAS_FIGEAGE = 200_000
# ... mais « 200 appels » dépend du fournisseur : à 101 blocs par appel (dRPC, mesuré), 200 000 blocs
# font ~1 980 appels et ~10 min — un amorçage de 49 000 blocs tenait en UN segment, écrit à la toute
# fin, et un refus au milieu (run 36469251579) perdait TOUT. Le pas est donc aussi borné en APPELS :
# au plus PAS_FIGEAGE_APPELS tranches du client entre deux écritures.
PAS_FIGEAGE_APPELS = 200


class RepriseError(RuntimeError):
    """Échec BRUYANT de la lecture des journaux : couverture, identité, écriture."""


def _bn(lg):
    v = lg["blockNumber"]
    return int(v, 16) if isinstance(v, str) else int(v)


def _li(lg):
    v = lg["logIndex"]
    return int(v, 16) if isinstance(v, str) else int(v)


def _canon(lg):
    """Projection canonique d'un journal : ce qui doit être IDENTIQUE entre deux lectures."""
    return {
        "address": (lg.get("address") or "").lower(),
        "topics": [t.lower() for t in (lg.get("topics") or [])],
        "data": (lg.get("data") or "0x").lower(),
        "blockNumber": _bn(lg),
        "logIndex": _li(lg),
        "blockHash": (lg.get("blockHash") or "").lower() or None,
        "transactionHash": (lg.get("transactionHash") or "").lower() or None,
    }


def empreinte_journaux(logs):
    """sha256 de la liste canonique triée par (bloc, index). Rend (empreinte, cardinal)."""
    c = sorted((_canon(lg) for lg in logs), key=lambda x: (x["blockNumber"], x["logIndex"]))
    payload = json.dumps(c, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest(), len(c)


def filtrer_topics(logs, topics):
    """Filtre LOCAL par `topic0`, équivalent au filtre `topics=[[t1, t2, …]]` du nœud."""
    if not topics:
        return list(logs)
    if len(topics) != 1:
        raise RepriseError("ARRÊT : seul un filtre sur topic0 est pris en charge localement.")
    voulus = {t.lower() for t in (topics[0] if isinstance(topics[0], list) else [topics[0]])}
    return [lg for lg in logs if lg.get("topics") and lg["topics"][0].lower() in voulus]


def _sha_fichier(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def _ecrire_atomique(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _verifier_couverture(intervalles, de, a):
    """Les intervalles doivent être contigus, ordonnés, et recouvrir EXACTEMENT [de, a]."""
    iv = [x for x in intervalles if x[1] >= x[0]]
    if not iv:
        raise RepriseError(f"COUVERTURE VIDE : aucun intervalle pour [{de}, {a}].")
    if iv[0][0] != de:
        raise RepriseError(f"COUVERTURE : commence à {iv[0][0]}, le déploiement est au bloc {de}.")
    for i in range(1, len(iv)):
        if iv[i][0] != iv[i - 1][1] + 1:
            raise RepriseError(f"COUVERTURE NON CONTIGUË : {iv[i - 1]} puis {iv[i]}.")
    if iv[-1][1] != a:
        raise RepriseError(
            f"COUVERTURE : s'arrête au bloc {iv[-1][1]}, la chaîne annonce {a}. La borne vient de la "
            f"CHAÎNE, pas du point de reprise (KE#130).")
    total = sum(y - x + 1 for x, y in iv)
    if total != a - de + 1:
        raise RepriseError(f"COUVERTURE : {total} blocs couverts pour {a - de + 1} attendus.")
    return total


class Magasin:
    """Le cache figé sur disque : un curseur + des segments immuables."""

    def __init__(self, state_dir, identite):
        self.dir = os.path.join(state_dir, DOSSIER)
        self.path = os.path.join(self.dir, CURSEUR)
        self.identite = identite            # {"chain_id", "rewards", "deploy_block"}

    def charger(self):
        """Rend (sha256 du curseur | None, [(segment, journaux)], problème | None). Ne lit PAS la chaîne."""
        if not os.path.exists(self.path):
            return None, [], None
        sha = None
        try:
            with open(self.path, "rb") as fh:
                brut = fh.read()
            sha = hashlib.sha256(brut).hexdigest()
            cur = json.loads(brut)
        except (OSError, ValueError) as e:
            return sha, [], f"curseur illisible ({e}) : repris depuis zéro."
        if cur.get("format") != FORMAT:
            return sha, [], f"curseur au format {cur.get('format')}, {FORMAT} attendu : repris depuis zéro."
        ident = {k: cur.get(k) for k in self.identite}
        if ident != self.identite:
            return sha, [], (f"curseur d'une AUTRE identité ({ident} ≠ {self.identite}) : un cache d'un "
                             f"autre contrat ou d'une autre chaîne n'est jamais réutilisé.")
        segments = []
        attendu = self.identite["deploy_block"]
        for s in cur.get("segments", []):
            p = os.path.join(self.dir, s["fichier"])
            if not os.path.exists(p):
                return sha, [], f"segment {s['fichier']} ABSENT : cache incomplet, repris depuis zéro."
            got = _sha_fichier(p)
            if got != s["sha256"]:
                return sha, [], (f"segment {s['fichier']} ALTÉRÉ (sha256 {got[:16]}… ≠ "
                                  f"{s['sha256'][:16]}…) : repris depuis zéro.")
            if s["de"] != attendu or s["à"] < s["de"] - 1:
                return sha, [], f"segments non contigus au bloc {s['de']} : repris depuis zéro."
            with open(p, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if len(doc["journaux"]) != s["n"]:
                return sha, [], f"segment {s['fichier']} : cardinal {len(doc['journaux'])} ≠ {s['n']}."
            ts = {int(k): v for k, v in doc.get("horodatages", {}).items()}
            manquants = {_bn(lg) for lg in doc["journaux"]} - set(ts)
            if manquants:
                return sha, [], (f"segment {s['fichier']} : {len(manquants)} bloc(s) à journaux sans "
                                 f"horodatage figé : repris depuis zéro.")
            segments.append((s, doc["journaux"], ts))
            attendu = s["à"] + 1
        return sha, segments, None

    def reprises(self):
        """Reprises FORCÉES (divergence, cache rejeté) inscrites au curseur : `[{génération, bloc}]`.

        REGISTRE, plus garde : depuis le 2026-09-29, le différentiel segmenté (`segments.py`) ne le lit plus. Il
        voit une plage re-figée par son CONTENU (contrôle (i) : empreinte du cache ≠ empreinte vérifiée), ce qui
        couvre aussi un cache rejeté puis reconstruit, que ce registre ne voyait pas. Il reste inscrit au
        curseur pour l'examen humain d'une divergence.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return list(json.load(fh).get("reprises", []))
        except (OSError, ValueError):
            return []

    def ecrire(self, sha_lu, segments, nouveau, reprise_forcee=None):
        """Écrit `nouveau` (ou rien) et le curseur. Rend un dict d'état d'écriture.

        `segments` : [(meta, journaux, horodatages)] retenus après vérification ; `nouveau` :
        (de, à, hash, journaux, horodatages) ou None. Cède si le curseur a changé depuis `sha_lu`.
        """
        os.makedirs(self.dir, exist_ok=True)
        verrou = open(os.path.join(self.dir, ".verrou"), "a+")
        try:
            fcntl.flock(verrou.fileno(), fcntl.LOCK_EX)
            actuel = _sha_fichier(self.path) if os.path.exists(self.path) else None
            if actuel != sha_lu:
                return {"écrit": False,
                        "pourquoi": "curseur modifié par une passe concurrente depuis sa lecture : "
                                    "écriture CÉDÉE (les journaux de cette passe restent justes)."}
            metas = [m for m, _, _ in segments]
            if nouveau is not None:
                de, a, h, logs, ts = nouveau
                nom = f"seg-{de}-{a}.json"
                _ecrire_atomique(os.path.join(self.dir, nom),
                                 {"de": de, "à": a, "hash_fin": h, "journaux": logs,
                                  "horodatages": {str(k): v for k, v in sorted(ts.items())}})
                metas.append({"de": de, "à": a, "hash_fin": h, "fichier": nom, "n": len(logs),
                              "sha256": _sha_fichier(os.path.join(self.dir, nom))})
                segments = segments + [(metas[-1], logs, ts)]
            compacte = False
            if len(metas) > MAX_SEGMENTS:
                de, a, h = metas[0]["de"], metas[-1]["à"], metas[-1]["hash_fin"]
                tous = [lg for _, lgs, _ in segments for lg in lgs]
                tts = {}
                for _, _, t in segments:
                    tts.update(t)
                nom = f"seg-{de}-{a}.json"
                _ecrire_atomique(os.path.join(self.dir, nom),
                                 {"de": de, "à": a, "hash_fin": h, "journaux": tous,
                                  "horodatages": {str(k): v for k, v in sorted(tts.items())}})
                metas = [{"de": de, "à": a, "hash_fin": h, "fichier": nom, "n": len(tous),
                          "sha256": _sha_fichier(os.path.join(self.dir, nom))}]
                compacte = True
            if compacte:
                segments = [(metas[0], tous, tts)]
            reprises = self.reprises()
            if reprise_forcee is not None:
                # génération = horloge en ns : strictement croissante d'une écriture à l'autre, et
                # supérieure à tout ce qu'un différentiel a déjà vu même si l'ancien curseur était illisible.
                g = max([time.time_ns()] + [r["génération"] + 1 for r in reprises])
                reprises.append({"génération": g, "bloc": int(reprise_forcee)})
            cur = dict(self.identite)
            cur.update({"format": FORMAT, "segments": metas, "écrit_le_ts": int(time.time()),
                        "reprises": reprises[-50:]})
            _ecrire_atomique(self.path, cur)
            # nettoyage des orphelins, APRÈS le point de validation
            gardes = {m["fichier"] for m in metas} | {CURSEUR, ".verrou"}
            for f in os.listdir(self.dir):
                if f.startswith("seg-") and f not in gardes:
                    os.remove(os.path.join(self.dir, f))
            return {"écrit": True, "segments": len(metas), "compacté": compacte,
                    "figé_jusqu_à": metas[-1]["à"] if metas else None,
                    "sha": _sha_fichier(self.path), "retenus": segments}
        finally:
            fcntl.flock(verrou.fileno(), fcntl.LOCK_UN)
            verrou.close()


class LecteurJournaux:
    """Point d'entrée unique des journaux de `SpindexRewards`, en mode `complet` ou `incrémental`."""

    def __init__(self, client, settings, mode=None):
        self.client = client
        self.s = settings
        self.mode = mode or getattr(settings, "reprise", None) or "complet"
        if self.mode not in MODES:
            raise RepriseError(f"ARRÊT : mode de reprise inconnu « {self.mode} » ({MODES}).")
        def _int(x):
            return None if x is None else int(x)
        self.identite = {"chain_id": _int(settings.chain_id),
                         "rewards": (settings.rewards or "").lower() or None,
                         "deploy_block": _int(settings.deploy_block)}
        self.magasin = Magasin(settings.state_dir, self.identite)
        # {bloc: horodatage} des blocs FIGÉS (≤ finalized, hash vérifié) : immuables tant que la chaîne
        # est la même, ce que la vérification du point de reprise établit à chaque passe.
        self.horodatages_figes = {}

    # ------------------------------------------------------------------ utilitaires

    def _get(self, de, a):
        """Journaux [de, a] SANS filtre de topic (le filtre est local, pour que le cache serve à tous)."""
        if a < de:
            return [], []
        return self.client.get_logs_chunked(self.s.rewards, None, de, a)

    def _controler(self, logs, de, a):
        """Défense en profondeur : un nœud qui ne respecte pas le filtre ne doit rien faire figer."""
        for lg in logs:
            if (lg.get("address") or "").lower() != self.identite["rewards"]:
                raise RepriseError(f"ARRÊT : journal d'une autre adresse ({lg.get('address')}) servi "
                                   f"pour {self.identite['rewards']} : rien n'est figé.")
            if not de <= _bn(lg) <= a:
                raise RepriseError(f"ARRÊT : journal au bloc {_bn(lg)} hors de la plage demandée [{de}, {a}].")

    def _relier_a_la_chaine_verifiee(self, lgs, fin_seg):
        """Fournisseurs par RÔLE : les journaux viennent d'un fournisseur, les BORNES (tête, finalized, hash
        des blocs) de l'autre. Sans ce lien, un fournisseur de journaux EN RETARD (plage rendue vide) ou
        servant une AUTRE chaîne au même chainId serait figé « vérifié » — et le différentiel D, relu chez
        le même fournisseur, ne pourrait pas le contredire. Deux jambes, avant toute écriture (KE#130) :

        (a) la tête du fournisseur des journaux a ATTEINT la fin du segment ;
        (b) chaque bloc portant des journaux : TOUS les `blockHash` servis == le hash de ce bloc lu chez le
            fournisseur de l'ÉTAT. Coût nul en appels : le bloc est lu de toute façon pour son horodatage.

        Limite, écrite : un bloc où le fournisseur des journaux OMET des journaux sans rien en rendre n'est
        pas couvert par (b) — seule une seconde source de journaux le verrait.
        Rend les horodatages {bloc: ts} des blocs à journaux."""
        tete_j = int(self.client.must_journaux("eth_blockNumber", []), 16)
        if tete_j < fin_seg:
            raise RepriseError(
                f"ARRÊT : le fournisseur des JOURNAUX annonce la tête {tete_j}, en RETARD sur la fin du segment "
                f"à figer ({fin_seg}) : une plage qu'il n'a pas atteinte serait figée vide. Rien n'est figé.")
        ts = {}
        for bn in sorted({_bn(x) for x in lgs}):
            b = self.client.block(bn)
            h = (b.get("hash") or "").lower()
            servis = {(x.get("blockHash") or "").lower() for x in lgs if _bn(x) == bn}
            if servis != {h}:
                raise RepriseError(
                    f"ARRÊT : bloc {bn} — les journaux servis portent blockHash {sorted(servis)}, le "
                    f"fournisseur de l'ÉTAT lit {h} : journaux d'une AUTRE chaîne (ou d'un embranchement). "
                    f"Rien n'est figé.")
            ts[bn] = int(b["timestamp"], 16)
        return ts

    # ------------------------------------------------------------------ lecture

    def lire(self, head, fin_bn, fin_hash, topics=None, ecrire=True, echeance=None, lire_queue=True):
        """Rend (journaux ≤ finalized, journaux de la queue ]finalized, tête], rapport).

        `head`, `fin_bn`, `fin_hash` sont LUS SUR LA CHAÎNE par l'appelant pendant la passe : ce sont
        eux, et non le cache, qui bornent la couverture (KE#130).

        `echeance` / `lire_queue` (mode incrémental, différentiel segmenté seulement, 2026-09-29) : le figeage
        s'arrête PROPREMENT entre deux pas une fois l'échéance passée (chaque pas est déjà persisté) — le
        rapport le DIT (`figeage_interrompu`) et la couverture n'est alors exigée que jusqu'au dernier bloc
        figé ; la queue non figée n'est pas lue si l'appelant n'en a pas l'usage. La passe n'utilise ni l'un
        ni l'autre : son comportement est inchangé.
        """
        dep = self.identite["deploy_block"]
        if fin_bn > head:
            raise RepriseError(f"ARRÊT : finalized {fin_bn} devant la tête {head}.")
        fin_eff = max(dep - 1, fin_bn)       # `finalized` peut précéder le déploiement sur une chaîne neuve
        appels_avant = self.client.stats.get("calls", 0)
        t0 = time.time()
        self.horodatages_figes = {}
        rapport = {"mode": self.mode, "de": dep, "à": head, "finalized": fin_bn,
                   "borne": "tête et finalized lus sur la chaîne pendant la passe (KE#130)"}

        if self.mode == "complet":
            final, c1 = self._get(dep, fin_eff)
            queue, c2 = self._get(fin_eff + 1, head)
            _verifier_couverture(c1 + c2, dep, head)
            rapport.update({"reprise_depuis": dep, "divergence": None})
        else:
            sha_lu, segments, probleme = self.magasin.charger()
            divergence = None
            abandonnes = 0
            verifs = 0
            # --- VÉRIFICATION du point de reprise contre la chaîne, en reculant s'il le faut.
            while segments:
                meta = segments[-1][0]
                if meta["à"] > fin_eff:
                    motif = (f"le cache est figé jusqu'au bloc {meta['à']}, mais la chaîne ne finalise "
                             f"que jusqu'au bloc {fin_bn} : chaîne réinitialisée, nœud différent, ou "
                             f"finalité qui recule")
                else:
                    # Le hash est TOUJOURS relu sur la chaîne : soit dans la réponse `finalized` de
                    # cette passe, soit par un appel dédié. Jamais pris dans le cache lui-même.
                    h = fin_hash if meta["à"] == fin_bn else self.client.block(meta["à"])["hash"]
                    verifs += 1
                    if (h or "").lower() == (meta["hash_fin"] or "").lower():
                        break
                    motif = (f"le hash du bloc {meta['à']} lu sur la chaîne ({h}) diffère de celui "
                             f"figé ({meta['hash_fin']})")
                divergence = divergence or {"motif": motif, "bloc": meta["à"]}
                segments = segments[:-1]
                abandonnes += 1
            if divergence:
                divergence.update({
                    "segments_abandonnés": abandonnes,
                    "repris_depuis": segments[-1][0]["à"] + 1 if segments else dep,
                    "conséquence": "les journaux au-delà sont RELUS depuis la chaîne. Sur la chaîne de "
                                   "production, un bloc finalisé qui change est un incident en soi "
                                   "(finalité violée ou nœud qui ment) : à examiner, pas à absorber."})
            reprise = segments[-1][0]["à"] + 1 if segments else dep
            cache = [lg for _, lgs, _ in segments for lg in lgs]
            for _, _, t in segments:
                self.horodatages_figes.update(t)
            couv = [(m["de"], m["à"]) for m, _, _ in segments]
            sha_courant = sha_lu
            ecriture = {"écrit": False, "pourquoi": "rien de neuf à figer" if ecrire
                        else "écriture non demandée"}
            forcee = reprise if (abandonnes or probleme) else None
            if ecrire and fin_eff < reprise and forcee is not None:
                ecriture = self.magasin.ecrire(sha_courant, segments, None, reprise_forcee=forcee)
                forcee = None
                sha_courant, segments = ecriture.get("sha", sha_courant), ecriture.get("retenus", segments)
            # --- figeage PROGRESSIF de ]reprise, finalized] : par pas de PAS_FIGEAGE blocs, chaque pas
            # écrit son segment. Un rattrapage long (premier démarrage après des mois) interrompu par
            # un arrêt reprend donc où il en était, au lieu de recommencer de zéro à chaque fois.
            neuf = []
            n_segments_ecrits = 0
            cede = not ecrire
            interrompu = None
            debut = reprise
            span = getattr(self.client, "max_log_span", None)
            pas = min(PAS_FIGEAGE, PAS_FIGEAGE_APPELS * span) if span else PAS_FIGEAGE
            while debut <= fin_eff:
                if echeance is not None and time.time() > echeance:
                    interrompu = debut - 1
                    break
                fin_seg = min(fin_eff, debut + pas - 1)
                lgs, c = self._get(debut, fin_seg)
                self._controler(lgs, debut, fin_seg)
                couv += c
                # Horodatages des blocs portant un journal : lus UNE fois, figés avec le segment.
                # Sans cela, compte à rebours, racines et reconstruction relisent à CHAQUE passe un
                # horodatage par événement — un second coût qui croît sans borne, caché derrière le
                # premier.
                if hasattr(self.client, "must_journaux"):
                    ts = self._relier_a_la_chaine_verifiee(lgs, fin_seg)
                else:
                    ts = {bn: self.client.block_timestamp(bn) for bn in sorted({_bn(x) for x in lgs})}
                self.horodatages_figes.update(ts)
                neuf.extend(lgs)
                if not cede:
                    h = fin_hash if fin_seg == fin_bn else self.client.block(fin_seg)["hash"]
                    ecriture = self.magasin.ecrire(sha_courant, segments, (debut, fin_seg, h, lgs, ts),
                                                   reprise_forcee=forcee)
                    forcee = None
                    if ecriture["écrit"]:
                        sha_courant, segments = ecriture["sha"], ecriture["retenus"]
                        n_segments_ecrits += 1
                    else:
                        cede = True
                debut = fin_seg + 1
            if interrompu is not None or not lire_queue:
                # couverture exigée jusqu'au dernier bloc figé (lu), jamais au-delà ; la queue n'est pas lue
                borne = interrompu if interrompu is not None else fin_eff
                queue, c2 = [], []
                if borne >= dep:
                    _verifier_couverture(couv, dep, borne)
            else:
                queue, c2 = self._get(fin_eff + 1, head)
                _verifier_couverture(couv + c2, dep, head)
            final = cache + neuf
            ecriture = {k: v for k, v in ecriture.items() if k not in ("retenus",)}
            ecriture["segments_écrits_cette_passe"] = n_segments_ecrits
            rapport.update({"figeage_interrompu": interrompu, "queue_lue": interrompu is None and lire_queue,
                            "reprise_depuis": reprise, "cache_blocs": reprise - dep,
                            "cache_journaux": len(cache), "neuf_figé_blocs": max(0, fin_eff - reprise + 1),
                            "vérifications_de_hash": verifs,
                            "divergence": divergence, "cache_rejeté": probleme, "écriture": ecriture})
        self._controler(queue, fin_eff + 1, head)
        cles = [(_bn(lg), _li(lg)) for lg in final + queue]
        if len(set(cles)) != len(cles):
            raise RepriseError("ARRÊT : deux journaux partagent (bloc, index) : cache et relecture se "
                               "recouvrent, la base serait comptée deux fois.")
        rapport.update({"journaux_figés": len(final), "journaux_queue": len(queue),
                        "appels_rpc": self.client.stats.get("calls", 0) - appels_avant,
                        "durée_s": round(time.time() - t0, 3)})
        return filtrer_topics(final, topics), filtrer_topics(queue, topics), rapport

    def queue(self, fin_bn, head):
        """Relit la seule queue non figée ]finalized, tête] : ce que la comptabilité du burn rejoue quand
        elle doit relire à un NOUVEAU bloc de tête. La partie figée ne se relit pas deux fois."""
        fin_eff = max(self.identite["deploy_block"] - 1, fin_bn)
        logs, couv = self._get(fin_eff + 1, head)
        if head > fin_eff:
            _verifier_couverture(couv, fin_eff + 1, head)
        self._controler(logs, fin_eff + 1, head)
        return logs

    def lire_cache_seul(self):
        """Repli quand la chaîne est INJOIGNABLE : le cache figé, NON revérifié, et dit comme tel.

        Sert à une seule chose : que le compte à rebours J+90 survive à une panne du RPC. Les échéances
        connues ne font que se rapprocher ; ce qui manque (journaux postérieurs au cache) est nommé.
        """
        if self.mode != "incrémental":
            return None, "mode complet : aucun cache"
        _, segments, probleme = self.magasin.charger()
        if not segments:
            return None, probleme or "aucun cache figé"
        for _, _, t in segments:
            self.horodatages_figes.update(t)
        return ([lg for _, lgs, _ in segments for lg in lgs],
                f"cache figé jusqu'au bloc {segments[-1][0]['à']}, NON revérifié contre la chaîne")


# Les DIFFÉRENTIELS (incrémental confronté à une relecture de la chaîne) vivent dans `segments.py` depuis le
# 2026-09-29 : relus d'un seul tenant, ils ne tenaient plus dans un job de 36 min passé ~2 jours d'âge du
# contrat chez dRPC. Ils y sont REPRENABLES par segments à bornes fixes, avec un point de reprise vérifié.
