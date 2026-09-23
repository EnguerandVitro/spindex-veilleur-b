"""Amorçage du veilleur — À FAIRE DÈS LE DÉPLOIEMENT de `SpindexRewards` (arbitrage Q1 du coordinateur).

Pourquoi dès le déploiement : le premier remplissage du cache coûte ~1 appel par 1 000 blocs depuis le bloc de
déploiement. Le premier jour, c'est quelques centaines d'appels ; un mois plus tard, ~26 000 et des heures.

    python3 -B -m veilleur amorcer --instance a --tx-deploiement 0x<hash de la transaction de déploiement>

L'amorçage n'est DÉCLARÉ FAIT (`état: AMORCÉ`, sortie 0) que si les quatre preuves sont réunies :

  A. la transaction de déploiement est réussie, a créé EXACTEMENT `SPINDEX_REWARDS_ADDR`, dans EXACTEMENT
     `SPINDEX_REWARDS_DEPLOY_BLOCK` — un bloc de déploiement trop tardif ferait manquer des journaux pour
     toujours, trop précoce ne coûterait que des appels : on exige l'égalité ;
  B. TÉMOIN POSITIF (KE#121) : le bloc de déploiement porte le journal du constructeur
     `OwnershipTransferred(0x0, propriétaire)` émis par cette adresse. Il prouve à la fois que le bloc est le
     bon et que la lecture des journaux voit réellement le contrat (une adresse ou un filtre faux rendrait
     « zéro journal », indiscernable d'un contrat calme) ;
  C. le cache est figé jusqu'au `finalized` lu pendant l'amorçage, point de reprise vérifié par hash ;
  D. le différentiel COMPLET rend IDENTIQUE, sur un cardinal non nul (B le garantit).

Tant que `finalized` n'a pas dépassé le bloc de déploiement (~20 min après), rien n'est figeable :
`état: EN_ATTENTE_DE_FINALITÉ`, sortie 20, à relancer. Tout autre défaut : `REFUS`, sortie 10, motifs nommés.

Le REGISTRE d'amorçage (`<état>/amorcage.json`, 2026-09-22)
-----------------------------------------------------------
Un amorçage `AMORCÉ` écrit, en dernier et atomiquement (KE#112), le `chainId` LU SUR LE NŒUD pendant l'amorçage
(pas celui du `.env`), l'adresse, le bloc et la transaction de déploiement. C'est la « chaîne de l'amorçage » que
chaque passe et chaque différentiel comparent à `eth_chainId` relu ET à la chaîne configurée (`garde_chaine`).

Pourquoi pas le curseur du cache (`journaux/curseur.json`), qui porte aussi un `chain_id` : le curseur est
RÉÉCRIT par les passes, avec l'identité du `.env`. Un `.env` qui annonce une autre chaîne fait rejeter le cache
puis réécrire le curseur à SA chaîne : la référence serait tirée du sujet contrôlé (KE#130). Le registre, lui,
n'est écrit que par un amorçage qui a réuni ses quatre preuves, et un amorçage REFUSE d'écraser le registre
d'une autre chaîne (la garde lève avant toute lecture).

Sans registre, une passe planifiée ne lit rien : `erreur / amorcage_absent`. Ce n'est pas « pas de défaut
constaté », c'est « je ne peux pas prouver que je regarde la bonne chaîne » (KE#104 : une référence absente est
une SENTINELLE, jamais une liste vide).
"""
import json
import os
import time

from .chainread import ChainReadError
from .journaux import LecteurJournaux, _ecrire_atomique, differentiel

REGISTRE = "amorcage.json"
FORMAT_REGISTRE = 1


class ChaineInattendue(ChainReadError):
    """Le nœud, la configuration et l'amorçage ne désignent pas la même chaîne. Aucune lecture n'est faite."""
    code_battement = "chaine_inattendue"


class AmorcageAbsent(ChainReadError):
    """Aucun registre d'amorçage : la chaîne de référence est inconnue, la passe ne lit rien."""
    code_battement = "amorcage_absent"


def chemin_registre(state_dir):
    return os.path.join(state_dir, REGISTRE)


def lire_registre(state_dir):
    """Rend le registre, ou None s'il est ABSENT. Illisible ou incomplet = exception : jamais « absent »."""
    p = chemin_registre(state_dir)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        raise ChaineInattendue(f"ARRÊT : registre d'amorçage {p} illisible ({e}) : la chaîne de référence est "
                               f"inconnue, rien n'est lu.") from e
    cid = doc.get("chain_id")
    if doc.get("format") != FORMAT_REGISTRE or isinstance(cid, bool) or not isinstance(cid, int):
        raise ChaineInattendue(f"ARRÊT : registre d'amorçage {p} au format inattendu (format "
                               f"{doc.get('format')}, chain_id {cid!r}) : rien n'est lu.")
    return doc


def ecrire_registre(state_dir, chain_id, rewards, deploy_block, tx_hash, instance):
    doc = {"format": FORMAT_REGISTRE, "chain_id": int(chain_id), "rewards": (rewards or "").lower(),
           "deploy_block": int(deploy_block), "tx_deploiement": tx_hash, "instance": instance,
           "source_chain_id": "eth_chainId lu sur le nœud pendant l'amorçage", "amorcé_le_ts": int(time.time())}
    _ecrire_atomique(chemin_registre(state_dir), doc)
    return doc


def garde_chaine(client, settings, exiger_amorcage):
    """`eth_chainId` RELU (jamais mis en cache) == chaîne configurée == chaîne de l'amorçage.

    Appelée au DÉBUT de chaque passe, de chaque différentiel et de chaque vérification signée, AVANT toute
    autre lecture : un écart lève `ChaineInattendue` et rien n'est lu ni attesté. `exiger_amorcage` : les
    tâches planifiées l'exigent (`AmorcageAbsent` sinon) ; l'amorçage lui-même et les vérifications à la main
    comparent au registre s'il existe.
    """
    lu = client.chain_id()
    configure = int(settings.chain_id)
    reg = lire_registre(settings.state_dir)
    amorce = None if reg is None else reg["chain_id"]
    ecarts = []
    if lu != configure:
        ecarts.append(f"le nœud annonce chainId={lu}, la configuration {configure}")
    if amorce is not None and amorce != lu:
        ecarts.append(f"le nœud annonce chainId={lu}, l'amorçage a été fait sur {amorce}")
    if ecarts:
        raise ChaineInattendue(
            "ARRÊT chaine_inattendue : " + " ; ".join(ecarts) + ". Aucune lecture, aucune attestation : "
            "surveiller la mauvaise chaîne rendrait un vert parfaitement faux.")
    if amorce is None and exiger_amorcage:
        raise AmorcageAbsent(
            f"ARRÊT amorcage_absent : aucun registre {chemin_registre(settings.state_dir)}. La chaîne de "
            f"l'amorçage est inconnue, la passe ne lit rien. Lancer `python3 -B -m veilleur amorcer "
            f"--instance <a|b> --tx-deploiement 0x…` (lecture seule, idempotent).")
    return {"chainId": lu, "configuré": configure, "amorçage": amorce}


def amorcer(v, s, tx_hash):
    motifs = []
    rep = {"instance": getattr(s, "instance", None), "rewards": s.rewards, "bloc_déploiement": s.deploy_block,
           "preuves": {}}
    rep["chaîne"] = v.preflight()

    # --- A. la transaction de déploiement
    rc = v.client.must("eth_getTransactionReceipt", [tx_hash])
    if rc is None:
        motifs.append("A : reçu introuvable pour cette transaction")
    else:
        bn = int(rc["blockNumber"], 16)
        ok = (rc.get("status") == "0x1" and (rc.get("contractAddress") or "").lower() == s.rewards
              and bn == int(s.deploy_block))
        rep["preuves"]["A_transaction"] = {"statut": rc.get("status"), "contrat_créé": rc.get("contractAddress"),
                                           "bloc": bn, "ok": ok}
        if not ok:
            motifs.append(f"A : la transaction a créé {rc.get('contractAddress')} au bloc {bn} (statut "
                          f"{rc.get('status')}) ; le .env annonce {s.rewards} au bloc {s.deploy_block}")

    # --- B. témoin positif : le journal du constructeur
    a = v.model.abi
    logs, _ = v.client.get_logs_chunked(s.rewards, [[a.topic0("OwnershipTransferred")]],
                                        int(s.deploy_block), int(s.deploy_block))
    ctor = [lg for lg in logs if len(lg.get("topics", [])) > 1 and int(lg["topics"][1], 16) == 0]
    rep["preuves"]["B_journal_du_constructeur"] = {"trouvés": len(ctor), "ok": len(ctor) == 1}
    if len(ctor) != 1:
        motifs.append(f"B : {len(ctor)} journal(aux) OwnershipTransferred(0x0, …) au bloc de déploiement, 1 "
                      f"attendu — bloc, adresse ou lecture des journaux faux")

    # --- C. le cache figé
    head, fin_bn, fin_hash, _ = v.chaine_passe()
    if fin_bn < int(s.deploy_block):
        rep["état"] = "EN_ATTENTE_DE_FINALITÉ" if not motifs else "REFUS"
        rep["motifs"] = motifs or [f"finalized ({fin_bn}) n'a pas encore atteint le bloc de déploiement : "
                                   f"rien n'est figeable, relancer dans ~20 min"]
        return rep
    lect = LecteurJournaux(v.client, s, mode="incrémental")
    _, _, r = lect.lire(head, fin_bn, fin_hash)
    _, segs, pb = lect.magasin.charger()
    fige = segs[-1][0]["à"] if segs else None
    rep["preuves"]["C_cache"] = {"figé_jusqu_à": fige, "finalized_lu": fin_bn, "divergence": r["divergence"],
                                 "cache_rejeté": pb, "ok": fige == fin_bn and pb is None}
    if fige != fin_bn or pb:
        motifs.append(f"C : cache figé jusqu'à {fige}, finalized lu {fin_bn}, problème : {pb}")

    # --- D. différentiel complet
    d = differentiel(v.client, s, head, fin_bn, fin_hash)
    rep["preuves"]["D_différentiel_complet"] = {"état": d["état"], "journaux": d["complet"]["journaux"],
                                                "ok": d["état"] == "IDENTIQUE"}
    if d["état"] != "IDENTIQUE":
        motifs.append(f"D : différentiel complet {d['état']}")

    rep["état"] = "AMORCÉ" if not motifs else "REFUS"
    rep["motifs"] = motifs
    if not motifs:
        # EN DERNIER, et seulement sur AMORCÉ : un amorçage refusé ne désigne aucune chaîne de référence.
        rep["registre"] = ecrire_registre(s.state_dir, rep["chaîne"]["chainId"], s.rewards, s.deploy_block,
                                          tx_hash, getattr(s, "instance", None))
        rep["ensuite"] = ("activer les timers de CETTE instance : systemctl --user enable --now "
                          f"spindex-veilleur@{rep['instance']}.timer "
                          f"spindex-veilleur-differentiel-quotidien@{rep['instance']}.timer "
                          f"spindex-veilleur-differentiel@{rep['instance']}.timer")
    return rep
