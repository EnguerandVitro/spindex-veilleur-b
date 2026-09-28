"""Mettre `config/chaine-46630.json` à jour depuis UN manifeste de déploiement — et le prouver sur la chaîne.

À lancer sur la machine du keeper, au REDÉPLOIEMENT, avant de pousser `b` :

    python3 -B outils/maj_chaine.py --manifeste ~/stockslot/contracts/deploy/manifestes/deploiement-46630-<date>.json

Ce que la commande REFUSE (sortie 2, la configuration n'est pas touchée) :
  * un manifeste hors de `contracts/deploy/manifestes/`, ou qui n'est pas un `deploiement-*` ;
  * un manifeste dont les contrôles de déploiement ne sont pas TOUS réussis (cardinal apparié, KE#111) ;
  * une chaîne différente de celle de la configuration ;
  * adresse, bloc ou transaction de `SpindexRewards` que la CHAÎNE ne confirme pas (reçu de la tx de
    création, empreinte du code en place) — le manifeste est un témoignage, la chaîne est l'autorité (KE#130) ;
  * un `SpindexRewards` ANTÉRIEUR à la séparation de domaine : `TAG_CLAIM()` / `TAG_DRAW()` doivent rendre
    les étiquettes des vecteurs dorés (`config/vecteurs-convention.json`, calculées par cast depuis le contrat
    source). Sans ce contrôle, `b` publierait des feuilles C-4 contre un contrat qui n'en calcule pas.
    Mesuré le 2026-09-28 : le déploiement actuel (`deploiement-46630-20260922T041522Z`) est refusé ICI,
    et c'est le comportement voulu.

La lecture de la chaîne passe par un RPC PUBLIC (celui du profil `robinhood-officiel`, lu dans le paquet
scellé), ou par `SPINDEX_MAJ_RPC_URL` s'il est posé dans l'environnement — jamais en argument (fuite
`VERCEL_TOKEN`). Aucune transaction n'est émise. La configuration est sauvegardée en `.bak` puis réécrite
atomiquement ; seuls `rewards`, `deploy_block`, `tx_deploiement` et leur provenance changent.

Le premier passage de `b` après cette mise à jour trouve un registre d'amorçage d'un AUTRE déploiement dans
l'état restauré : `executer.sh` l'archive (il ne le détruit pas) et ré-amorce contre la configuration.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import urllib.request

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ICI, "config", "chaine-46630.json")
VECTEURS = os.path.join(ICI, "config", "vecteurs-convention.json")
CHAMPS = ("rewards", "deploy_block", "tx_deploiement")


class Refus(RuntimeError):
    pass


def _paquet():
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    from veilleur.fournisseurs import PROFILS, USER_AGENT_DEFAUT
    from veilleur.keccak import keccak256
    return PROFILS, USER_AGENT_DEFAUT, keccak256


def _rpc(url, ua, methode, params):
    corps = json.dumps({"jsonrpc": "2.0", "id": 1, "method": methode, "params": params}).encode()
    req = urllib.request.Request(url, corps, {"content-type": "application/json", "user-agent": ua})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    if "error" in d:
        raise Refus(f"ARRÊT : {methode} refusé par le nœud : {d['error']}")
    return d.get("result")


def lire_manifeste(chemin, projet):
    base = os.path.realpath(os.path.join(projet, "contracts", "deploy", "manifestes"))
    reel = os.path.realpath(chemin)
    if os.path.dirname(reel) != base or not os.path.basename(reel).startswith("deploiement-"):
        raise Refus(f"ARRÊT : {chemin} n'est pas un manifeste `deploiement-*` de {base}.")
    with open(reel, encoding="utf-8") as fh:
        m = json.load(fh)
    ctl = m.get("controles") or {}
    detail = ctl.get("detail") or []
    ko = [d.get("controle") for d in detail if d.get("ok") is not True]
    if not detail or ko or ctl.get("executes") != ctl.get("reussis") or ctl.get("executes") != len(detail):
        raise Refus(f"ARRÊT : contrôles du déploiement non tous réussis (exécutés {ctl.get('executes')}, "
                    f"réussis {ctl.get('reussis')}, détail {len(detail)}, en échec {ko[:5]}).")
    r = (m.get("contrats") or {}).get("SpindexRewards") or {}
    dep = m.get("deploiement") or {}
    nouveau = {"rewards": str(r.get("adresse") or "").lower(), "deploy_block": r.get("bloc"),
               "tx_deploiement": str(r.get("tx") or "").lower()}
    if not (nouveau["rewards"].startswith("0x") and len(nouveau["rewards"]) == 42
            and isinstance(nouveau["deploy_block"], int) and len(nouveau["tx_deploiement"]) == 66):
        raise Refus(f"ARRÊT : SpindexRewards incomplet dans le manifeste : {nouveau}.")
    if dep.get("rewards_bloc") != nouveau["deploy_block"] or str(dep.get("rewards_tx")).lower() != nouveau["tx_deploiement"]:
        raise Refus("ARRÊT : le manifeste se contredit (contrats.SpindexRewards vs deploiement.rewards_*).")
    return m, r, nouveau, reel


def prouver_sur_la_chaine(m, r, nouveau, chain_id_config):
    PROFILS, ua, keccak256 = _paquet()
    url = os.environ.get("SPINDEX_MAJ_RPC_URL") or PROFILS["robinhood-officiel"]["url"]
    preuves = []
    cid = int(_rpc(url, ua, "eth_chainId", []), 16)
    if cid != int(m["chain_id"]) or cid != int(chain_id_config):
        raise Refus(f"ARRÊT : chaîne {cid}, manifeste {m['chain_id']}, configuration {chain_id_config}.")
    preuves.append(f"chainId {cid}")
    rc = _rpc(url, ua, "eth_getTransactionReceipt", [nouveau["tx_deploiement"]])
    if not rc or int(rc.get("status", "0x0"), 16) != 1 \
            or str(rc.get("contractAddress") or "").lower() != nouveau["rewards"] \
            or int(rc["blockNumber"], 16) != nouveau["deploy_block"]:
        raise Refus(f"ARRÊT : le reçu de {nouveau['tx_deploiement']} ne crée pas {nouveau['rewards']} "
                    f"au bloc {nouveau['deploy_block']} (reçu : {rc and (rc.get('contractAddress'), rc.get('blockNumber'), rc.get('status'))}).")
    preuves.append("reçu de création : adresse, bloc, statut")
    code = _rpc(url, ua, "eth_getCode", [nouveau["rewards"], "latest"])
    if hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() != r.get("runtime_sha256_onchain"):
        raise Refus("ARRÊT : le code en place à l'adresse n'a pas l'empreinte annoncée par le manifeste.")
    preuves.append("empreinte du code en place")
    # EN DERNIER : si tout le reste passe et que ceci refuse, le motif est C-4 et rien d'autre (KE#139).
    with open(VECTEURS, encoding="utf-8") as fh:
        pre = json.load(fh)["etiquettes_preimages_du_contrat"]
    for dom in ("claim", "draw"):
        attendu = "0x" + keccak256(pre[dom].encode()).hex()
        sel = "0x" + keccak256(f"TAG_{dom.upper()}()".encode())[:4].hex()
        try:
            lu = _rpc(url, ua, "eth_call", [{"to": nouveau["rewards"], "data": sel}, "latest"])
        except Refus:
            lu = None
        if str(lu).lower() != attendu:
            raise Refus(f"ARRÊT : SpindexRewards {nouveau['rewards']} est ANTÉRIEUR à la séparation de domaine "
                        f"(C-4) : TAG_{dom.upper()}() rend {lu}, attendu {attendu}. b ne doit pas être pointé "
                        f"sur ce contrat.")
    preuves.append("TAG_CLAIM / TAG_DRAW = étiquettes des vecteurs dorés (C-4)")
    return preuves


def mettre_a_jour(manifeste, projet, config=CONFIG, ecrire=True):
    with open(config, encoding="utf-8") as fh:
        cfg = json.load(fh)
    m, r, nouveau, reel = lire_manifeste(manifeste, projet)
    preuves = prouver_sur_la_chaine(m, r, nouveau, cfg["chain_id"])
    avant = {k: cfg.get(k) for k in CHAMPS}
    for k in CHAMPS:
        cfg[k] = nouveau[k]
    with open(reel, "rb") as fh:
        empreinte = hashlib.sha256(fh.read()).hexdigest()
    cfg.setdefault("_provenance", {})["rewards / deploy_block / tx_deploiement"] = (
        f"manifeste de déploiement {os.path.relpath(reel, projet)} (sha256 {empreinte}), écrit par "
        f"outils/maj_chaine.py après preuve sur la chaîne : {' ; '.join(preuves)}")
    if ecrire:
        shutil.copy2(config, config + ".bak")
        tmp = config + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=1)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, config)
    return avant, nouveau, preuves


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifeste", required=True)
    ap.add_argument("--projet", default=os.path.dirname(ICI), help="racine du projet (défaut : parent du dépôt)")
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("--a-blanc", action="store_true", help="tout vérifier, ne rien écrire")
    a = ap.parse_args(argv)
    try:
        avant, apres, preuves = mettre_a_jour(a.manifeste, a.projet, a.config, ecrire=not a.a_blanc)
    except Refus as e:
        print(str(e), file=sys.stderr)
        return 2
    for p in preuves:
        print(f"  prouvé : {p}")
    for k in CHAMPS:
        print(f"  {k} : {avant[k]} -> {apres[k]}")
    print("À BLANC : rien écrit." if a.a_blanc else
          f"configuration écrite ({a.config}, ancienne en .bak). Rejouer banc/preuves.sh, puis committer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
