"""Orchestration : rassembler les pièces, exécuter les contrôles, rendre un verdict signé.

L'ordre des opérations n'est pas décoratif.

1. **Gel AVANT.** `frozen.py check rewards` est joué avant toute lecture. Si le manifeste est absent ou
   qu'une empreinte a bougé, on ne mesure rien : un veilleur qui vérifie une table contre un contrat
   qui a changé entre-temps donne une garantie fausse.
2. **Lectures.** Journaux d'abord (ils remontent à la genèse, pour toujours), état ensuite (il ne dure
   que quelques minutes).
3. **Contrôles.** Aucun n'a le droit de « passer parce qu'il n'a pas pu s'exécuter ».
4. **Gel APRÈS.** Rejoué. Si les deux lectures diffèrent, le verdict n'est PAS publié : on a mesuré
   sur deux contrats différents et on ne sait pas lequel.
5. **Écriture.** Le document signé n'est écrit qu'ici, atomiquement (KE#112).

La fenêtre d'état est remesurée **à chaque passage**, et une fenêtre qui rétrécit sous le seuil
configuré lève une alerte : c'est un paramètre de sûreté tiré d'une mesure, il ne doit jamais devenir
une supposition datée.
"""
import subprocess
import sys
import time

from . import ledger as ledger_mod
from . import tables as tables_mod
from . import verdict as verdict_mod
from .attest import AttestKey
from .chainread import ChainReader, ChainReadError
from . import artefacts as _artefacts
from .chainabi import decode_event
from .controls import DrawEvidence, WeekEvidence, run_opendraw, run_postweek
from .longfuse import RootJournal, draws_report, weeks_report
from . import compte_a_rebours as car_mod
from .window_history import DureeHistory, WindowHistory, mesurer_fenetre
from .reconstruct import BlockTimestamps, replay, replay_both
from .rpc import RpcClient, RpcUnavailable
from .journaux import LecteurJournaux
from .amorcage import AmorcageAbsent, ChaineInattendue, garde_chaine


class _HorodatagesSansChaine:
    """Horodatages quand la chaîne est INJOIGNABLE : seulement ceux figés avec le cache. Un bloc absent
    est une EXCEPTION, jamais un zéro — un horodatage inventé déplacerait une échéance en silence."""

    def __init__(self, figes):
        self.cache = dict(figes)
        self.calls = 0

    def __call__(self, bn):
        if bn not in self.cache:
            raise RuntimeError(f"horodatage du bloc {bn} inconnu hors ligne (non figé)")
        return self.cache[bn]


class Veilleur:
    def __init__(self, settings, model, client=None):
        self.s = settings
        self.model = model
        self.client = client or RpcClient(settings.rpc_url)
        self.reader = ChainReader(self.client, model, settings)
        self.journaux = LecteurJournaux(self.client, settings)

    # ------------------------------------------------------------------ gel

    def frozen_check(self, family="rewards"):
        """Gel des artefacts.

        Sur un **lot publié**, `frozen.py` n'existe pas chez le tiers — et il n'a pas à exister : le
        manifeste du lot a DÉJÀ vérifié l'empreinte de chaque artefact au chargement, et il refuse un
        lot qui a bougé. La garantie est donc la même, portée par un autre mécanisme. Le choix est
        lié à la DISPOSITION des artefacts, pas à la présence d'un fichier : on ne peut pas
        contourner le gel chez nous en effaçant `frozen.py`.
        """
        art = _artefacts.resoudre(self.s.contracts_dir)
        if art.disposition == "lot publié":
            return {"famille": family, "code": 0, "état": "REMPLACÉ_PAR_LE_MANIFESTE_DU_LOT",
                    "sortie": [f"lot publié vérifié : {len(art.manifeste.get('fichiers', {}))} "
                               f"artefact(s) épinglés par sha256"]}
        cmd = [sys.executable, "-B", "script/frozen.py", "check", family]
        p = subprocess.run(cmd, cwd=self.s.contracts_dir, capture_output=True, text=True)
        return {"famille": family, "code": p.returncode,
                "sortie": (p.stdout or p.stderr).strip().splitlines()[:8]}

    # ------------------------------------------------------------------ chaîne

    def garde_chaine(self, exiger_amorcage=True):
        """`eth_chainId` relu à CHAQUE appel == chaîne configurée == chaîne de l'amorçage (`amorcage.py`).

        Lève `ChaineInattendue` (écart) ou `AmorcageAbsent` : dans les deux cas RIEN n'est lu ni attesté.
        """
        return garde_chaine(self.client, self.s, exiger_amorcage)

    def preflight(self):
        """Ce qui doit être vrai avant de prétendre vérifier quoi que ce soit.

        La garde de chaîne compare aussi au registre d'amorçage s'il existe ; elle ne l'EXIGE pas ici :
        `amorcer` passe par ce pré-vol avant d'avoir écrit le registre.
        """
        cid = self.garde_chaine(exiger_amorcage=False)["chainId"]
        return {
            "chainId": cid,
            "client": self.client.must("web3_clientVersion", []),
            "rewards": self.reader.verify_rewards_deployed(),
            "multicall3": self.reader.verify_multicall3(),
        }

    def lock_topics(self):
        a = self.model.abi
        return [[a.topic0(n) for n in ("Staked", "Unstaked", "BoostHalved", "Claimed")]]

    def chaine_passe(self, head=None):
        """Tête et `finalized`, LUS SUR LA CHAÎNE : ce sont eux qui bornent la couverture (KE#130).

        `finalized` est lu APRÈS la tête : sur une chaîne qui finalise instantanément (anvil), il peut
        la dépasser. On ne fige alors que jusqu'à la tête retenue, avec le hash de CE bloc-là.
        """
        head = self.client.block_number() if head is None else head
        fin = self.client.block("finalized")
        fin_bn = int(fin["number"], 16)
        if fin_bn > head:
            fin = self.client.block(head)
            fin_bn = head
        return head, fin_bn, fin["hash"], int(fin["timestamp"], 16)

    def journaux_passe(self, topics=None, head=None, ecrire=True):
        """Journaux de la passe par le lecteur (incrémental ou complet). Rend (≤finalized, queue, ctx).

        `head` : tête déjà lue par l'appelant (la vérification d'`openDraw` la fige en début de passe).
        """
        head, fin_bn, fin_hash, fin_ts = self.chaine_passe(head)
        final, queue, rapport = self.journaux.lire(head, fin_bn, fin_hash, topics=topics, ecrire=ecrire)
        return final, queue, {"tête": head, "finalized": fin_bn, "finalized_ts": fin_ts,
                              "lecture": rapport}

    def horodatages(self):
        """Horodatages de blocs : ceux FIGÉS avec le cache (lus une fois pour toutes), les autres relus."""
        bts = BlockTimestamps(self.client)
        bts.cache.update(self.journaux.horodatages_figes)
        return bts

    # ------------------------------------------------------------------ comptabilité du burn

    def _burn_ledger_at_head(self, final_logs, fin_bn):
        """Journaux ET `strandedBurn` au MÊME bloc, avec un second essai en cas de divergence.

        La partie figée (≤ finalized) est reprise telle quelle ; seule la QUEUE est relue à la tête
        courante, à chaque essai — c'est elle, et elle seule, qu'une réorganisation peut désaligner.
        """
        dernier = None
        for essai in (1, 2):
            head = self.client.block_number()
            logs = final_logs + self.journaux.queue(fin_bn, head)
            stranded = self.reader.stranded_burn(head)
            c, lignes = ledger_mod.control(self.model, logs, stranded)
            dernier = (c, lignes, head)
            if c.statut == "OK":
                return dernier
            lignes["essai"] = essai
        return dernier

    # ------------------------------------------------------------------ surveillance continue

    def surveillance(self, to_block=None):
        """Les absences, la comptabilité du burn, la fenêtre, les racines. Sans table, sans verdict.

        ORDRE ET ISOLEMENT, et c'est tout l'objet de cette fonction :
          1. lecture de la chaîne et des journaux — si elle échoue, repli sur le cache FIGÉ (non
             revérifié, et dit comme tel) pour que le compte à rebours reste calculable ;
          2. le COMPTE À REBOURS J+90 / J+30, en PREMIER, dans son propre `try` ;
          3. chaque section suivante dans son PROPRE `try` : une exception y devient une alerte
             `section_en_échec` nommée, elle n'emporte JAMAIS la sortie. Avant ce découpage, une
             exception de la comptabilité du burn faisait perdre le rapport entier, compte à rebours
             compris (défaut V1 relevé par l'atelier surveillance).
        """
        out = {"ts": int(time.time()), "alertes": [], "sections_en_échec": [], "bloc_tête": None}
        bts = BlockTimestamps(self.client)
        logs = None
        queue = []
        now_ts = None
        fin_bn = None

        # ---- 0. LA BONNE CHAÎNE, avant toute lecture (rapport testnet-46630 §3 : un `.env` à 4663 face à un
        # nœud 46630 battait `ok`). Un écart ou un amorçage absent LÈVE : aucun rapport, aucune lecture, pas
        # même le repli sur le cache — un rapport de la mauvaise chaîne est pire que pas de rapport.
        # Un `eth_chainId` ILLISIBLE (nœud en panne) n'est pas un écart : on ne lit alors RIEN sur la chaîne
        # (elle n'est pas prouvée), et on passe par le repli sur le cache figé, qui porte l'identité amorcée.
        chaine_non_verifiee = None
        try:
            out["chaîne"] = self.garde_chaine(exiger_amorcage=True)
        except (ChaineInattendue, AmorcageAbsent):
            raise
        except Exception as e:  # noqa: BLE001
            chaine_non_verifiee = f"eth_chainId illisible ({type(e).__name__} : {e}) : chaîne NON vérifiée"
            out["chaîne"] = {"erreur": chaine_non_verifiee}

        # ---- 1. lecture
        try:
            if chaine_non_verifiee:
                raise ChainReadError(chaine_non_verifiee + ", rien n'est lu sur le nœud")
            final, queue, lecture = self.journaux_passe()
            fin_bn = lecture["finalized"]
            if to_block is not None and to_block < fin_bn:
                final = [lg for lg in final if int(lg["blockNumber"], 16) <= to_block]
                fin_bn = to_block
            logs = final
            now_ts = lecture["finalized_ts"]
            bts = self.horodatages()
            out.update({"bloc_lecture": fin_bn, "bloc_tête": lecture["tête"],
                        "lecture_journaux": lecture["lecture"], "journaux": len(logs),
                        "couverture_blocs": fin_bn - self.s.deploy_block + 1})
            div = lecture["lecture"].get("divergence")
            if div:
                out["alertes"].append({"gravité": "P1", "source": "point de reprise",
                                       "clé": "point_de_reprise_divergent",
                                       "motif": div["motif"], "conséquence": div["conséquence"]})
            if lecture["lecture"].get("cache_rejeté"):
                out["alertes"].append({"gravité": "P1", "source": "point de reprise",
                                       "clé": "cache_rejeté", "motif": lecture["lecture"]["cache_rejeté"]})
        except Exception as e:  # noqa: BLE001 — une lecture impossible se DIT, elle ne tue pas la passe
            out["lecture_journaux"] = {"erreur": f"{type(e).__name__} : {e}"}
            out["sections_en_échec"].append("lecture")
            out["alertes"].append({"gravité": "P1", "source": "lecture de la chaîne",
                                   "clé": "section_en_échec:lecture",
                                   "motif": f"journaux illisibles : {type(e).__name__} : {e}"})
            try:
                logs, pourquoi = self.journaux.lire_cache_seul()
            except Exception as e2:  # noqa: BLE001
                logs, pourquoi = None, f"cache illisible : {e2}"
            out["repli_compte_à_rebours"] = pourquoi
            now_ts = int(time.time())       # horloge MURALE : la chaîne n'a pas répondu
            bts = _HorodatagesSansChaine(self.journaux.horodatages_figes)

        # ---- 2. COMPTE À REBOURS EN PREMIER, et quoi qu'il arrive ensuite.
        # C'est une alerte de premier rang, indépendante de l'état de santé du veilleur : le dommage
        # J+90 ne vient pas d'une anomalie, il vient du temps qui passe pendant que tout va bien.
        try:
            out["compte_à_rebours"] = car_mod.calculer(self.model, logs or [], now_ts, bts,
                                                       deploy_block=self.s.deploy_block)
            if logs is not None and out.get("repli_compte_à_rebours"):
                out["compte_à_rebours"]["source"] = out["repli_compte_à_rebours"]
        except Exception as e:  # noqa: BLE001
            out["compte_à_rebours"] = {
                "état": "NON_CALCULABLE", "échéances": [], "pire_gravité": "P1",
                "explication": f"calcul impossible : {type(e).__name__} : {e}. Ce n'est PAS « aucune "
                               f"échéance » (KE#105)."}
        out["alertes"].extend(car_mod.alertes(out["compte_à_rebours"]))

        # ---- 3. sections suivantes, chacune ISOLÉE
        def section(nom, fn):
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                out["sections_en_échec"].append(nom)
                out["alertes"].append({"gravité": "P1", "source": nom, "clé": f"section_en_échec:{nom}",
                                       "motif": f"{type(e).__name__} : {e}",
                                       "conséquence": "cette section n'a PAS été vérifiée à cette passe."})

        def absences():
            if logs is None:
                raise RuntimeError("aucun journal lu : absences non évaluables")
            out["semaines"] = weeks_report(self.model, logs, now_ts,
                                           self.s.week_unposted_alert_days, bts)
            out["tirages"] = draws_report(self.model, logs, now_ts,
                                          self.s.draw_unsettled_alert_days, bts)
            out["alertes"].extend(out["semaines"]["alertes"])
            out["alertes"].extend(out["tirages"]["alertes"])

        def burn():
            # La comptabilité du burn compare des JOURNAUX à un ÉTAT : les deux doivent être lus au
            # MÊME bloc. Or l'état n'est servi qu'à ~10 min de la tête, donc ce contrôle-là ne peut PAS
            # se jouer au bloc finalisé. Il se joue à la tête, et une divergence est REJOUÉE une fois
            # avant d'être déclarée : à la tête, une réorganisation peut désaligner journaux et état.
            if fin_bn is None:
                raise RuntimeError("chaîne injoignable : comptabilité non évaluable")
            c, lignes, bloc_burn = self._burn_ledger_at_head(logs, fin_bn)
            out["burn"] = {"contrôle": c.to_dict(), "lignes": lignes, "bloc": bloc_burn,
                           "pourquoi_pas_finalized": "l'état n'est plus servi à la profondeur de "
                                                     "`finalized` (fenêtre ~6 231 blocs < 12 031)."}
            if c.statut != "OK":
                out["alertes"].append({"gravité": "P0", "source": "comptabilité du burn",
                                       "clé": "comptabilite_burn", "motif": c.motif,
                                       "conséquence": "publication ARRÊTÉE : un écart est un journal "
                                                      "manqué, donc une base trouée."})

        def racines():
            if fin_bn is None:
                raise RuntimeError("chaîne injoignable : racines non évaluées")
            jr = RootJournal(self.s.state_dir)
            obs = jr.observe(self.model, logs, bts)
            jr.save()
            out["racines"] = obs
            out["alertes"].extend(obs["p0"])

        def fenetre():
            if chaine_non_verifiee:
                raise RuntimeError(chaine_non_verifiee + " : fenêtre non mesurée (aucune lecture d'une chaîne "
                                   "non prouvée)")
            hist = WindowHistory(self.s.state_dir)
            try:
                w = mesurer_fenetre(self.reader)
            except (ChainReadError, RpcUnavailable) as e:
                out["fenêtre_état"] = {"erreur": str(e)}
                out["alertes"].append({"gravité": "P1", "source": "fenêtre d'état",
                                       "clé": "fenêtre_non_mesurée", "motif": f"non mesurable : {e}"})
                return
            out["fenêtre_état"] = w
            out["fenêtre_meilleure_relevée_s"] = hist.meilleure_s
            out["fenêtre_besoin_s"] = self.s.window_need_s
            out["alertes"].extend(hist.alertes(w, self.s.window_alert_s, besoin_s=self.s.window_need_s))
            hist.ajouter(w).save()

        section("absences", absences)
        section("burn", burn)
        section("racines", racines)
        section("fenêtre", fenetre)

        out["appels_rpc"] = dict(self.client.stats)
        out["horodatages_lus"] = getattr(bts, "calls", 0)
        # Assertion de COUVERTURE : le compte à rebours DOIT être dans toute sortie de surveillance.
        # S'il pouvait manquer, son absence ressemblerait à « rien à signaler ».
        if "compte_à_rebours" not in out or "état" not in out["compte_à_rebours"]:
            raise RuntimeError(
                "ARRÊT : sortie de surveillance sans compte à rebours. Une échéance J+90 qui "
                "disparaît du rapport est exactement le silence que ce contrôle existe pour rompre.")
        return out

    # ------------------------------------------------------------------ avant postWeek

    def check_postweek(self, week_id, table_source=None):
        gel_avant = self.frozen_check()
        ctx = {"gel_avant": gel_avant}
        alertes = []
        if gel_avant["code"] != 0:
            return self._verdict("postWeek", verdict_mod.INDISPONIBLE,
                                 {"weekId": str(week_id), "racine": None},
                                 {"suite": "postWeek", "verdict": "INDISPONIBLE",
                                  "contrôles": [], "motifs": ["GEL"]},
                                 ctx,
                                 [{"gravité": "P0", "source": "gel",
                                   "motif": "le gel des artefacts `rewards` n'est pas vérifié. On ne "
                                            "mesure rien, on ne publie rien."}])
        ctx["chaîne"] = self.preflight()
        table = (table_source if isinstance(table_source, tables_mod.Table)
                 else tables_mod.load(table_source or self.s.tables_base_url, "week", week_id))

        head, fin_bn, fin_hash, _ = self.chaine_passe()
        ctx["bloc_lecture"] = {
            "journaux_jusqu_à": {"tag": "finalized", "numéro": fin_bn, "hash": fin_hash},
            "état_lu_à": {"tag": "latest", "numéro": head},
            "pourquoi": "aucune lecture d'ÉTAT n'est possible à un bloc finalisé : la fenêtre d'état "
                        "(~6 231 blocs) est PLUS COURTE que la distance de `finalized` (~12 031 "
                        "blocs). Les journaux, eux, remontent à la genèse — ce sont donc eux qui "
                        "portent la preuve réorg-sûre, et la lecture d'état à la tête ne sert que de "
                        "confirmation fraîche.",
        }

        ev = WeekEvidence()
        try:
            ev.week_tête = self.reader.week(table.week_id, head)
        except Exception as e:  # noqa: BLE001
            ev.erreurs["tête"] = str(e)
        try:
            a = self.model.abi
            logs, _queue, lecture = self.journaux.lire(
                head, fin_bn, fin_hash, topics=[[a.topic0("WeekFunded"), a.topic0("WeekPosted")]])
            ctx["journaux"] = {"nombre": len(logs), "de": self.s.deploy_block, "à": fin_bn,
                               "lecture": lecture}
            total = 0
            dernier_cumul = None
            racine = None
            n = 0
            for lg in sorted(logs, key=lambda x: (int(x["blockNumber"], 16), int(x["logIndex"], 16))):
                t0 = lg["topics"][0].lower()
                if t0 == a.topic0("WeekFunded").lower():
                    d = decode_event(a, "WeekFunded", lg)
                    if d["weekId"] != table.week_id:
                        continue
                    total += d["usdgAmount"]
                    dernier_cumul = d["funded"]
                    n += 1
                elif t0 == a.topic0("WeekPosted").lower():
                    d = decode_event(a, "WeekPosted", lg)
                    if d["weekId"] != table.week_id:
                        continue
                    racine = d["root"]
            ev.funded_journaux = total
            ev.funded_évènement = dernier_cumul
            ev.racine_journaux = racine
            ev.n_versements = n
        except Exception as e:  # noqa: BLE001
            ev.erreurs["journaux"] = f"journaux indisponibles : {e}"

        ctx["enveloppe"] = {"versements_vus": ev.n_versements,
                            "funded_journaux": None if ev.funded_journaux is None
                            else str(ev.funded_journaux),
                            "funded_tête": None if not ev.week_tête else str(ev.week_tête["funded"])}
        suite = run_postweek(table, ev)

        engagement = {
            "weekId": str(table.week_id),
            "racine": "0x" + table.root.hex(),
            "totalUsdg": str(table.total),
            "leafCount": table.leaf_count,
            "snapshotBlock": table.snapshot_block,
            "table_sha256": table.raw_sha256,
            "table_origine": table.origin,
        }
        v = {"GO": verdict_mod.GO, "REFUS": verdict_mod.REFUS,
             "INDISPONIBLE": verdict_mod.INDISPONIBLE}[suite.verdict]
        if v == verdict_mod.GO:
            ctx["table_archivée"] = tables_mod.archive(table, self.s.state_dir)
        ctx["gel_après"] = self.frozen_check()
        if ctx["gel_après"]["code"] != 0 or ctx["gel_après"]["sortie"] != gel_avant["sortie"]:
            v = verdict_mod.INDISPONIBLE
            alertes.append({"gravité": "P0", "source": "gel",
                            "motif": "le gel lu AVANT et APRÈS les mesures diffère : les contrôles ont "
                                     "porté sur deux états du contrat et on ne sait pas lequel."})
        ctx["appels_rpc"] = dict(self.client.stats)
        return self._verdict("postWeek", v, engagement, suite.to_dict(), ctx, alertes)

    # ------------------------------------------------------------------ avant openDraw

    def check_opendraw(self, week_id, table_source=None):
        gel_avant = self.frozen_check()
        ctx = {"gel_avant": gel_avant}
        alertes = []
        if gel_avant["code"] != 0:
            return self._verdict("openDraw", verdict_mod.INDISPONIBLE,
                                 {"weekId": str(week_id), "racine": None},
                                 {"suite": "openDraw", "verdict": "INDISPONIBLE",
                                  "contrôles": [], "motifs": ["GEL"]}, ctx,
                                 [{"gravité": "P0", "source": "gel",
                                   "motif": "gel des artefacts `rewards` non vérifié."}])
        ctx["chaîne"] = self.preflight()
        table = (table_source if isinstance(table_source, tables_mod.Table)
                 else tables_mod.load(table_source or self.s.tables_base_url, "draw", week_id))

        ev = DrawEvidence()
        bts = BlockTimestamps(self.client)
        head = self.client.block_number()
        head_blk = self.client.block(head)
        head_ts = int(head_blk["timestamp"], 16)
        snap = table.snapshot_block

        # --- fenêtre d'état, remesurée à CHAQUE passage
        t_passe = time.time()
        durees = DureeHistory(self.s.state_dir)
        hist = WindowHistory(self.s.state_dir)
        try:
            win = mesurer_fenetre(self.reader, head=head)
            ev.fenêtre = win
            alertes.extend(hist.alertes(win, self.s.window_alert_s, besoin_s=self.s.window_need_s))
            hist.ajouter(win).save()
        except (ChainReadError, RpcUnavailable) as e:
            win = {"erreur": str(e)}
            ev.fenêtre = win
            alertes.append({"gravité": "P1", "source": "fenêtre d'état", "motif": str(e)})

        ctx["fenêtre_état"] = win
        ctx["instantané"] = {"bloc": snap, "tête": head}

        if snap > head:
            ev.erreurs["direct"] = (f"le bloc d'instantané {snap} est DEVANT la tête {head} : la table "
                                    f"annonce un instantané qui n'existe pas encore.")
        else:
            snap_blk = self.client.block(snap)
            snap_ts = int(snap_blk["timestamp"], 16)
            ctx["instantané"].update({"hash": snap_blk["hash"], "ts": snap_ts,
                                      "âge_s": head_ts - snap_ts})
            prof_ok = win.get("profondeur_ok_max_blocs")
            if prof_ok is not None and (head - snap) > prof_ok:
                ev.erreurs["direct"] = (
                    f"HORS FENÊTRE : l'instantané est à {head - snap} blocs de la tête, la fenêtre "
                    f"d'état mesurée n'en sert que {prof_ok} ({win.get('fenêtre_s')} s). La lecture "
                    f"directe exigée par §21 n'est PAS exécutable. Ce n'est pas un refus de la table, "
                    f"c'est un « je n'ai pas pu vérifier » — et il ne vaut pas feu vert.")
            age = head_ts - snap_ts
            if age > self.s.publish_deadline_s:
                alertes.append({
                    "gravité": "P1", "source": "règle de publication",
                    "clé": "publication_tardive",
                    "motif": f"la table a été soumise au veilleur {age} s après le bloc d'instantané, "
                             f"au-delà des {self.s.publish_deadline_s} s de consigne.",
                    "conséquence": "la vérification doit tenir DANS la fenêtre d'état ; chaque seconde "
                                   "perdue ici est prise sur la seule preuve normative.",
                })
            # --- borne DÉRIVÉE, pas choisie : fenêtre mesurée − 3 × durée de vérification observée.
            derive = durees.delai_max_admis(win.get("fenêtre_s"))
            ctx["délai_max_admis"] = derive
            if derive.get("dérivé"):
                if not derive["utilisable"]:
                    alertes.append({
                        "gravité": "P0", "source": "marge de vérification",
                        "clé": "marge_derivee_negative",
                        "motif": f"fenêtre {derive['fenêtre_s']} s − 3 × {derive['durée_max_observée_s']} s "
                                 f"= {derive['délai_max_admis_s']} s : la vérification ne tient plus "
                                 f"dans la fenêtre avec sa marge.",
                        "conséquence": derive["si_négatif"],
                    })
                elif age > derive["délai_max_admis_s"]:
                    alertes.append({
                        "gravité": "P1", "source": "marge de vérification",
                        "clé": "marge_derivee_depassee",
                        "motif": f"instantané vieux de {age} s pour un délai dérivé de "
                                 f"{derive['délai_max_admis_s']} s "
                                 f"({derive['formule']}, {derive['observations']} observation(s), "
                                 f"{derive['fiabilité']}).",
                        "conséquence": "une passe qui échoue ne pourra plus être rejouée à temps.",
                    })
            else:
                alertes.append({
                    "gravité": "INFO", "source": "marge de vérification",
                    "clé": "marge_non_derivable", "motif": derive["pourquoi"]})

            # --- journaux : de la genèse du contrat à la TÊTE (superset), puis deux rejeux
            try:
                final, queue, lecture = self.journaux_passe(topics=self.lock_topics(), head=head)
                logs = final + queue
                bts.cache.update(self.journaux.horodatages_figes)
                ctx["journaux"] = {"nombre": len(logs), "de": self.s.deploy_block, "à": head,
                                   "lecture": lecture["lecture"]}
                logs_snap = [lg for lg in logs
                             if (int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str)
                                 else lg["blockNumber"]) <= snap]
                rec_snap, rapport = replay_both(self.model, logs_snap, bts)
                ev.recoupement_halving = rapport
                ev.stakers_reconstruits = rec_snap.stakers()
                # OD-J, jambe (2) : la somme des montants REJOUÉS. Elle ne traverse aucune lecture
                # d'état, donc elle reste comparable à `totalStaked()` même si le nœud ment sur
                # `stakeOf` — et elle tombe dès qu'un `Staked` a été omis du flux (KE#130).
                ev.total_staked_reconstruit = sum(s.amount for s in rec_snap.states.values())
                ev.poids_reconstruits = rec_snap.effective(self.model, snap_ts)
                rec_head = replay(self.model, logs, bts, halve_source="event")
                ev.poids_à_la_tête = rec_head.effective(self.model, head_ts)
                ctx["reconstruction"] = {"stakers_au_bloc_instantané": len(ev.stakers_reconstruits),
                                         "stakers_à_la_tête": len(rec_head.stakers()),
                                         "compteurs": rec_snap.counters,
                                         "recoupement_halving": rapport}
            except Exception as e:  # noqa: BLE001
                ev.erreurs["reconstruction"] = f"reconstruction impossible : {e}"

            cibles = sorted(set(ev.stakers_reconstruits or set()) | set(table.players))
            ev.cibles = cibles
            # --- OD-J : l'agrégat que la chaîne tient ELLE-MÊME sur l'ensemble inénumérable des
            # stakers. C'est la seule borne de cette passe qui ne vienne pas du sujet (KE#130), et
            # elle se lit AU BLOC D'INSTANTANÉ — pas à la tête : comparer une somme mesurée au bloc
            # d'instantané à un total lu à la tête serait faux à chaque `stake` survenu entre les
            # deux. Un échec de lecture ne se confond pas avec un total nul (KE#105).
            try:
                ev.total_staked_onchain = self.reader.total_staked(snap)
            except Exception as e:  # noqa: BLE001
                ev.erreurs["total_staked"] = (
                    f"`totalStaked()` illisible au bloc d'instantané {snap} : {e}. La borne "
                    f"on-chain de l'exhaustivité manque — OD-J est INDISPONIBLE, jamais OK.")
            # --- lectures VIVANTES à la tête : c'est ce qui prouve la reconstruction en continu
            if cibles:
                try:
                    ev.effectif_vivant = self.reader.read_many("effectiveStakeOf", cibles, head)
                except Exception as e:  # noqa: BLE001
                    ev.erreurs["vivant"] = f"lectures vivantes impossibles : {e}"
                # --- lecture DIRECTE au bloc d'instantané : le contrôle normatif de §21
                if "direct" not in ev.erreurs:
                    try:
                        ev.stake_direct = self.reader.read_many("stakeOf", cibles, snap)
                        ev.effectif_direct = self.reader.read_many("effectiveStakeOf", cibles, snap)
                    except Exception as e:  # noqa: BLE001
                        ev.erreurs["direct"] = f"lecture directe au bloc d'instantané impossible : {e}"
            else:
                ev.erreurs["reconstruction"] = ev.erreurs.get(
                    "reconstruction",
                    "aucune adresse à lire : ni staker reconstruit, ni feuille. Un ensemble vide ne "
                    "doit jamais faire passer un contrôle d'exhaustivité (KE#111).")

        suite = run_opendraw(self.reader, table, ev, head)

        engagement = {
            "weekId": str(table.week_id),
            "racine": "0x" + table.root.hex(),
            "totalWeight": str(table.total),
            "leafCount": table.leaf_count,
            "prizeToken": table.prize_token,
            "prizeAmount": None if table.prize_amount is None else str(table.prize_amount),
            "snapshotBlock": table.snapshot_block,
            "snapshotBlockHash": ctx["instantané"].get("hash"),
            "table_sha256": table.raw_sha256,
            "table_origine": table.origin,
        }
        v = {"GO": verdict_mod.GO, "REFUS": verdict_mod.REFUS,
             "INDISPONIBLE": verdict_mod.INDISPONIBLE}[suite.verdict]
        if v == verdict_mod.GO:
            ctx["table_archivée"] = tables_mod.archive(table, self.s.state_dir)
            # Le bloc d'instantané n'est PAS finalisé — il ne peut pas l'être, la fenêtre d'état est
            # plus courte que la distance à `finalized`. On le dit, et on exige la confirmation.
            ctx["confirmation_requise"] = {
                "pourquoi": "le bloc d'instantané est nécessairement NON FINALISÉ : la fenêtre d'état "
                            "(~10 min) est plus courte que la distance de `finalized` (~20 min). Le feu "
                            "vert porte donc sur un bloc encore réorganisable.",
                "quoi": f"rejouer `confirmer --bloc {table.snapshot_block} --hash "
                        f"{ctx['instantané'].get('hash')}` une fois `finalized` passé ce bloc : il "
                        f"vérifie que le hash n'a pas changé (sortie 0 CONFIRMÉ, 10 CADUC).",
                "si_le_hash_a_changé": "le feu vert est CADUC : alerte P0, ne pas s'en prévaloir.",
            }
        ctx["gel_après"] = self.frozen_check()
        if ctx["gel_après"]["code"] != 0 or ctx["gel_après"]["sortie"] != gel_avant["sortie"]:
            v = verdict_mod.INDISPONIBLE
            alertes.append({"gravité": "P0", "source": "gel",
                            "motif": "le gel diffère avant / après les mesures."})
        ctx["appels_rpc"] = dict(self.client.stats)
        ctx["horodatages_lus"] = bts.calls
        ctx["lectures"] = dict(self.reader.calls)
        # La durée de CETTE passe alimente la borne dérivée des passes suivantes. On ne l'enregistre
        # que si la passe a réellement fait le travail : une passe avortée mesurerait une durée
        # courte et RELÂCHERAIT la borne — exactement le mauvais sens.
        durée = time.time() - t_passe
        ctx["durée_de_vérification_s"] = round(durée, 3)
        if ev.effectif_direct is not None:
            durees.ajouter(durée, portée="openDraw complet").save()
        return self._verdict("openDraw", v, engagement, suite.to_dict(), ctx, alertes)

    # ------------------------------------------------------------------ confirmation a posteriori

    def confirmer(self, snapshot_block, snapshot_hash):
        """Re-contrôle du bloc d'instantané une fois `finalized` passé dessus."""
        fin = self.client.block("finalized")
        fin_bn = int(fin["number"], 16)
        if fin_bn < snapshot_block:
            return {"état": "PAS_ENCORE", "finalized": fin_bn, "instantané": snapshot_block,
                    "explication": "la finalité n'a pas encore atteint le bloc d'instantané."}
        b = self.client.block(snapshot_block)
        même = b["hash"].lower() == (snapshot_hash or "").lower()
        return {"état": "CONFIRMÉ" if même else "CADUC",
                "finalized": fin_bn, "instantané": snapshot_block,
                "hash_attendu": snapshot_hash, "hash_lu": b["hash"],
                "explication": "" if même else
                "le bloc d'instantané a été réorganisé : le feu vert émis sur ce bloc est CADUC. "
                "Alerte P0, ne pas s'en prévaloir."}

    # ------------------------------------------------------------------ verdict

    def _verdict(self, action, v, engagement, suite_dict, ctx, alertes, portée="complète"):
        doc = verdict_mod.build(action, v, engagement, suite_dict, ctx, alertes, portée=portée)
        if not getattr(self.s, "attest_key_file", None):
            # Exécutant TIERS : il rejoue nos contrôles, il n'atteste pas à notre place. Fabriquer
            # une signature ici serait pire qu'inutile — ce serait un feu vert qui n'engage personne.
            return verdict_mod.sans_signature(
                doc, "aucune clé d'attestation configurée : exécution de vérification publique.")
        key = AttestKey.load(self.s.attest_key_file)
        return verdict_mod.sign(doc, key)
