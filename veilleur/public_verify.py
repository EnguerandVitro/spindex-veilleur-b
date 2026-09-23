"""**Le point d'entrée public.** Un tiers, une table, une URL RPC — le même verdict que nous.

Pourquoi il existe
------------------
La règle « le Safe s'abstient tant que le veilleur n'a pas donné son feu vert » transforme une panne
DURABLE du veilleur en semaines jamais publiées, donc en **balayage J+90** : la règle de sécurité
produisait elle-même le dommage qu'elle devait empêcher. La réponse n'est pas de l'assouplir, c'est
de faire en sorte que **n'importe qui puisse refaire la vérification**. Elle ne porte que sur des
données publiques — les journaux de la chaîne et la table publiée — donc elle est reproductible, et
une panne de NOTRE instance cesse d'être une panne de la GARANTIE.

Ce que ce module garantit, et qui est testé depuis un dossier VIERGE
--------------------------------------------------------------------
- **aucun chemin en dur** : tout se résout depuis l'emplacement du paquet ou depuis des arguments ;
- **aucun `.env` privé** : le mode vérification n'en lit aucun. Les coordonnées de la chaîne
  viennent du **lot publié** (`veilleur/public/MANIFESTE.json`), qui ne contient que du public ;
- **aucune clé** : le verdict rendu est **NON SIGNÉ**, explicitement. Un tiers ne doit pas fabriquer
  une signature ; ce qu'il produit vaut par son `empreinte_reproductible`, qui doit égaler la nôtre ;
- **une seule fonction** : `verifier(...)`, et une seule commande.

Deux portées, et elles ne se valent pas
---------------------------------------
- **`table seule`** (sans RPC) : racine, pavage, totaux, doublons. Rejouable **pour toujours**, même
  des mois après que la fenêtre d'état s'est refermée. **Ne vaut jamais feu vert** : ce sont exactement
  les contrôles que la table à une feuille au nom du keeper satisfait, et le verdict le dit.
- **`complète`** (avec RPC) : tout, y compris l'exhaustivité et l'égalité des poids — mais seulement
  **à l'intérieur de la fenêtre d'état**, qui dure une dizaine de minutes.
"""
import json
import os

from . import artefacts as _artefacts
from . import tables as tables_mod
from . import verdict as verdict_mod
from .chainabi import RewardsModel
from .controls import run_table_seule
from .config import verifier_besoin
from .rpc import RpcClient
from .window_history import BESOIN_DEFAUT_S


class PublicVerifyError(RuntimeError):
    pass


class ChaineParLot:
    """Réglages tirés du LOT PUBLIÉ, jamais d'un `.env`. Tout est public par construction."""

    def __init__(self, racine, rpc_url=None, surcharges=None):
        art = _artefacts.resoudre(racine)
        man = art.manifeste or {}
        ch = dict(man.get("chaîne") or {})
        ch.update({k: v for k, v in (surcharges or {}).items() if v is not None})
        self.artefacts_racine = racine
        self.disposition = art.disposition
        self.contracts_dir = racine
        self.rpc_url = rpc_url or ch.get("rpc_url_suggéré")
        self.chain_id = ch.get("chain_id")
        self.rewards = (ch.get("rewards") or "").lower() or None
        self.deploy_block = ch.get("deploy_block")
        self.multicall3 = (ch.get("multicall3") or "").lower() or None
        self.tables_base_url = ch.get("tables_base_url")
        # Réglages de sûreté : valeurs de consigne publiées, pas des secrets.
        self.publish_deadline_s = int(ch.get("publish_deadline_s") or 300)
        self.window_alert_s = int(ch.get("window_alert_s") or 720)
        self.window_need_s = int(ch.get("window_need_s") or BESOIN_DEFAUT_S)
        verifier_besoin(self.window_need_s, self.publish_deadline_s, self.window_alert_s)
        self.max_multicall_batch = int(ch.get("multicall_batch") or 4000)
        self.week_unposted_alert_days = int(ch.get("week_unposted_alert_days") or 7)
        self.draw_unsettled_alert_days = int(ch.get("draw_unsettled_alert_days") or 3)
        # Aucune clé : un exécutant tiers ne signe pas à notre place (le verdict rendu est NON SIGNÉ).
        self.attest_key_file = None
        # L'état (historique de fenêtre, journal des racines) reste local et jetable chez un tiers :
        # il sert à SA continuité, il ne fait pas partie de la garantie.
        import tempfile
        self.state_dir = os.path.join(tempfile.gettempdir(), "spindex-veilleur-public")
        self.window_probe_to = None
        self.window_probe_data = "0x18160ddd"
        # Reconstruction COMPLÈTE depuis le bloc de déploiement, toujours : c'est la garantie
        # « reproductible par n'importe qui ». Un tiers ne doit dépendre d'aucun cache — ni du nôtre,
        # ni d'un cache qu'il aurait lui-même laissé dans un dossier temporaire partagé.
        self.reprise = "complet"

    def pret_pour_la_chaine(self):
        manquants = [n for n, v in (("chain_id", self.chain_id), ("rewards", self.rewards),
                                    ("deploy_block", self.deploy_block),
                                    ("multicall3", self.multicall3), ("rpc_url", self.rpc_url))
                     if v in (None, "")]
        return (not manquants), manquants


def charger_table(chemin_ou_url):
    """Lit la table telle qu'elle est publiée. Le `type` et le `weekId` viennent de la TABLE :
    un tiers a un fichier ou une URL, pas notre arborescence."""
    if chemin_ou_url.startswith("https://"):
        import urllib.request
        req = urllib.request.Request(chemin_ou_url,
                                     headers={"user-agent": "spindex-veilleur-public/1"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
        except Exception as e:  # noqa: BLE001
            raise PublicVerifyError(f"INDISPONIBLE : {chemin_ou_url} illisible ({e!r}).") from e
        origine = chemin_ou_url
    elif chemin_ou_url.startswith("http://"):
        raise PublicVerifyError("ARRÊT : HTTP clair refusé — une table modifiable en vol ne prouve rien.")
    else:
        if not os.path.exists(chemin_ou_url):
            raise PublicVerifyError(f"INDISPONIBLE : {chemin_ou_url} n'existe pas.")
        with open(chemin_ou_url, "rb") as fh:
            raw = fh.read()
        origine = os.path.basename(chemin_ou_url)     # jamais le chemin absolu : il n'est pas public
    try:
        tete = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        raise PublicVerifyError(f"ARRÊT : table illisible : {e!r}") from e
    kind = tete.get("type")
    if kind not in ("week", "draw"):
        raise PublicVerifyError(f"ARRÊT : `type` absent ou inconnu dans la table (lu : {kind!r}).")
    wid = tete.get("weekId")
    if not isinstance(wid, str) or not wid.isdigit():
        raise PublicVerifyError("ARRÊT : `weekId` doit être une chaîne décimale.")
    return tables_mod.parse(raw, origine, kind, int(wid))


def verifier(table, rpc_url=None, racine_artefacts=None, surcharges_chaine=None):
    """LE point d'entrée. Rend une enveloppe NON SIGNÉE, comparable par `empreinte_reproductible`.

    `table` : chemin local ou URL https. `rpc_url` : absente ⇒ portée « table seule ».
    """
    racine = racine_artefacts or _artefacts.racine_par_defaut()
    t = charger_table(table)
    s = ChaineParLot(racine, rpc_url=rpc_url, surcharges=surcharges_chaine)
    model = RewardsModel(racine)

    action = "openDraw" if t.kind == "draw" else "postWeek"
    engagement = {
        "weekId": str(t.week_id),
        "racine": "0x" + t.root.hex(),
        ("totalWeight" if t.kind == "draw" else "totalUsdg"): str(t.total),
        "leafCount": t.leaf_count,
        "snapshotBlock": t.snapshot_block,
        "table_sha256": t.raw_sha256,
        "table_origine": t.origin,
    }
    if t.kind == "draw":
        engagement["prizeToken"] = t.prize_token
        engagement["prizeAmount"] = None if t.prize_amount is None else str(t.prize_amount)

    from .chainabi import IMPLEMENTATION_KECCAK
    contexte = {
        "artefacts": _artefacts.resoudre(racine).to_dict(),
        "outil": "veilleur.public_verify",
        "rien_de_notre_infrastructure": True,
        # Publié pour que l'exécutant sache quelle implémentation a servi. Ce champ ne fait PAS
        # partie de l'empreinte reproductible : les deux implémentations doivent donner le même
        # résultat, et si elles divergeaient c'est le test différentiel qui doit le dire, pas une
        # empreinte qui changerait selon la machine.
        "implémentation_keccak": IMPLEMENTATION_KECCAK,
    }

    if not rpc_url:
        suite, avert = run_table_seule(t)
        contexte["avertissement_de_portée"] = avert
        v = {"GO": verdict_mod.GO, "REFUS": verdict_mod.REFUS,
             "INDISPONIBLE": verdict_mod.INDISPONIBLE}[suite.verdict]
        # Une portée réduite ne rend JAMAIS `GO` : ce mot voudrait dire « le Safe peut signer », et il
        # ne le peut pas sur ces contrôles-là. On rend « COHÉRENTE » via un verdict INDISPONIBLE dont
        # le motif est la portée, pas une panne — et le texte le distingue explicitement.
        if v == verdict_mod.GO:
            v = verdict_mod.INDISPONIBLE
            contexte["table_cohérente_avec_sa_racine"] = True
            contexte["pourquoi_pas_GO"] = (
                "tous les contrôles HORS LIGNE passent : la table est cohérente avec la racine "
                "publiée. Ce n'est PAS un feu vert — l'exhaustivité et l'égalité des poids, les deux "
                "seuls contrôles qui portent la garantie, exigent la chaîne.")
        doc = verdict_mod.build(action, v, engagement, suite.to_dict(), contexte,
                                portée="table seule")
        return verdict_mod.sans_signature(
            doc, "vérification publique hors ligne : aucun exécutant tiers ne doit fabriquer une "
                 "signature de veilleur.")

    ok, manquants = s.pret_pour_la_chaine()
    if not ok:
        contexte["coordonnées_manquantes"] = manquants
        doc = verdict_mod.build(
            action, verdict_mod.INDISPONIBLE, engagement,
            {"suite": action, "verdict": "INDISPONIBLE", "contrôles": [],
             "motifs": ["COORDONNÉES_DE_CHAINE_ABSENTES"]},
            contexte,
            [{"gravité": "P1", "source": "lot publié",
              "motif": f"le lot ne porte pas {manquants} : le contrat n'est probablement pas encore "
                       f"déployé. On refuse plutôt que de vérifier contre une adresse vide."}],
            portée="complète")
        return verdict_mod.sans_signature(doc, "coordonnées de chaîne absentes du lot publié.")

    from .service import Veilleur                    # import tardif : le mode hors ligne n'en a pas besoin
    v = Veilleur(s, model, client=RpcClient(s.rpc_url))
    return (v.check_opendraw if t.kind == "draw" else v.check_postweek)(t.week_id, table_source=t)
