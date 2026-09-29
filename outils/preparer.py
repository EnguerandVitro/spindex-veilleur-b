"""Préparer l'exécution : écrire le `.env` et poser la clé d'attestation, SANS jamais les imprimer.

Ce que ce fichier ne fait pas, et pourquoi
------------------------------------------
- **Il ne crée AUCUNE clé.** La clé d'attestation de l'instance `b` est créée par l'utilisateur, hors
  ligne, sur sa machine, et collée dans un secret GitHub. Un job qui fabriquerait sa propre clé
  n'attesterait rien : la clé publique changerait à chaque exécution, et personne ne pourrait dire
  quelle clé est la bonne. Ici on *pose* le secret dans un fichier, c'est tout.
- **Il ne fait passer aucun secret par la ligne de commande.** Les valeurs arrivent par
  l'environnement et sont lues avec `os.environ`. Un secret en argument se retrouve dans les hints
  d'erreur, dans `ps`, et dans les traces des outils (fuite `VERCEL_TOKEN` du 2026-09-11).
- **Il n'imprime jamais une valeur secrète**, même tronquée, même en cas d'erreur. Les messages
  nomment la CLÉ, pas la valeur — comme `veilleur/config.py:audit_env_file`.

Le `.env` est écrit avec **toutes les valeurs entre apostrophes simples** (KE#107), puis relu par
l'auditeur du paquet scellé (`veilleur.config.audit_env_file`) : on ne se contente pas d'écrire
correctement, on fait vérifier par le consommateur. Une valeur qui contient elle-même une apostrophe
ou un retour à la ligne est un ARRÊT : elle casserait la citation, et c'est exactement le piège que
KE#107 décrit.

    python3 -B outils/preparer.py --config config/chaine-46630.json --etat <dossier>

Variables d'environnement lues (aucune n'a de valeur par défaut) :
    SPINDEX_B_RPC_URL         URL RPC        (secret GitHub)
    SPINDEX_B_ATTEST_KEY_HEX  clé Ed25519    (secret GitHub, 64 caractères hexadécimaux)
"""
import argparse
import json
import os
import re
import stat
import sys

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")


class PreparerError(RuntimeError):
    pass


def _secret(nom):
    v = os.environ.get(nom)
    if not v:
        raise PreparerError(
            f"ARRÊT : le secret {nom} est absent ou vide. Le job ne devine pas sa configuration et ne "
            f"se rabat sur rien : sans lui, il n'y a pas de veilleur b, il y a un job qui ment.")
    return v.strip()


def _citable(cle, valeur):
    """Une valeur qui casserait la citation simple est un ARRÊT. La valeur n'est JAMAIS imprimée."""
    if "'" in valeur:
        raise PreparerError(
            f"ARRÊT : la valeur de {cle} contient une apostrophe simple. Le `.env` du veilleur exige "
            f"des apostrophes simples (KE#107) et il n'existe pas d'échappement à l'intérieur : la "
            f"valeur serait tronquée en silence. Corriger le secret.")
    if "\n" in valeur or "\r" in valeur:
        raise PreparerError(
            f"ARRÊT : la valeur de {cle} contient un retour à la ligne (copié-collé d'un secret sur "
            f"plusieurs lignes ?). Le `.env` serait coupé en deux affectations dont une illisible.")
    return valeur


def ecrire_env(chemin, paires):
    """Écrit le `.env`, 0600, ATOMIQUEMENT (KE#112), toutes valeurs entre apostrophes simples."""
    lignes = ["# ÉCRIT PAR outils/preparer.py — ne pas éditer à la main, ne pas committer.",
              "# Toute valeur entre apostrophes simples : `source .env` est une EXÉCUTION de shell (KE#107).",
              ""]
    for k, v in paires:
        lignes.append(f"{k}='{_citable(k, str(v))}'")
    os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
    tmp = chemin + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lignes) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, chemin)
    os.chmod(chemin, 0o600)


def poser_cle(chemin, hexa):
    """Pose la clé d'attestation, 0600. La valeur ne transite ni par argv ni par un `echo`."""
    if not _HEX32.match(hexa):
        raise PreparerError(
            "ARRÊT : SPINDEX_B_ATTEST_KEY_HEX n'est pas 64 caractères hexadécimaux (32 octets). "
            "La longueur lue n'est pas imprimée : elle en dit déjà trop sur un secret. Régénérer la "
            "clé hors ligne en suivant le README, section « La clé d'attestation de b ».")
    os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
    if os.path.exists(chemin):
        os.chmod(chemin, 0o600)
        os.remove(chemin)
    fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(hexa.lower() + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    st = os.stat(chemin)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):   # témoin positif du chmod (KE#121)
        raise PreparerError(f"ARRÊT : {chemin} reste lisible par le groupe ou par tous "
                            f"(mode {oct(st.st_mode & 0o777)}).")


WORKFLOW = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".github", "workflows", "veilleur-b.yml")


def periode_du_cron(chemin=WORKFLOW):
    """Période de la passe, en secondes, LUE dans le cron du workflow (jamais recopiée).

    Seule la forme ``*/N * * * *`` est acceptée : c'est celle du workflow livré. Toute autre forme,
    plusieurs crons, ou aucun cron → ARRÊT qui le dit. Un planificateur qu'on ne sait pas lire ne doit
    pas produire une cadence devinée : la déclaration servirait ensuite de borne à la surveillance.
    """
    with open(chemin, encoding="utf-8") as fh:
        crons = re.findall(r"^\s*-\s*cron:\s*[\"']([^\"']+)[\"']", fh.read(), re.M)
    if len(crons) != 1:
        raise PreparerError(f"ARRÊT : {len(crons)} cron(s) dans {chemin} ; il en faut exactement un.")
    m = re.fullmatch(r"\*/(\d+) \* \* \* \*", crons[0].strip())
    if not m:
        raise PreparerError(f"ARRÊT : cron « {crons[0]} » non reconnu (forme attendue : « */N * * * * »).")
    return int(m.group(1)) * 60


def _domaine(url):
    """Domaine enregistrable (deux derniers labels) — `lb.drpc.org` et `robinhood-testnet.drpc.org`
    sont le même fournisseur. Ne rend JAMAIS l'URL (elle porte souvent une clé d'API)."""
    from urllib.parse import urlparse
    h = (urlparse(url).hostname or "").lower().rstrip(".")
    return ".".join(h.split(".")[-2:]) if h.count(".") >= 1 else h


def profil_rpc(url_secrete, declare):
    """Le profil de fournisseur que le `.env` doit porter, ou ARRÊT.

    Le fournisseur est IDENTIFIÉ par le domaine de l'URL secrète, confronté aux profils MESURÉS du paquet
    scellé (`veilleur/fournisseurs.py:PROFILS` — lus, jamais recopiés). Un domaine connu IMPOSE son
    profil : `b` est sur dRPC (101 blocs par plage, refus en HTTP 400), et sans le profil il redécouvre
    la limite à CHAQUE passe en se faisant refuser (rapport veilleur §13). Déclarer un profil que l'URL
    contredit est aussi un ARRÊT : ce serait les hypothèses d'un autre fournisseur. Un domaine inconnu
    sans profil déclaré est admis (mode découverte, borné par le client) ; avec un profil déclaré, non.
    Les messages nomment les DOMAINES des profils, jamais l'URL secrète.
    """
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    from veilleur.fournisseurs import PROFILS
    dom = _domaine(url_secrete)
    detectes = sorted(n for n, p in PROFILS.items() if _domaine(p["url"]) == dom)
    if len(detectes) > 1:
        raise PreparerError(f"ARRÊT : plusieurs profils mesurés partagent un domaine ({detectes}).")
    if declare is not None and declare not in PROFILS:
        raise PreparerError(f"ARRÊT : rpc_profil « {declare} » n'est pas un profil mesuré "
                            f"({', '.join(sorted(PROFILS))}).")
    if detectes and declare != detectes[0]:
        raise PreparerError(
            f"ARRÊT : l'URL RPC secrète est chez le fournisseur du profil « {detectes[0]} » "
            f"(domaine {_domaine(PROFILS[detectes[0]]['url'])}), la configuration déclare "
            f"« {declare or 'AUCUN profil'} ». Poser `\"rpc_profil\": \"{detectes[0]}\"` dans la configuration "
            f"de chaîne : sans lui le client redécouvre la limite de plage en se faisant refuser.")
    if not detectes and declare is not None:
        raise PreparerError(
            f"ARRÊT : la configuration déclare le profil « {declare} », mais l'URL RPC secrète n'est chez "
            f"AUCUN fournisseur mesuré. Mesurer ce fournisseur, ou retirer `rpc_profil`.")
    return declare


TACHES_B = {"passe": "PASSE", "differentiel-quotidien": "DIFFERENTIEL_QUOTIDIEN",
            "differentiel-complet": "DIFFERENTIEL_COMPLET"}


def planification_env(c):
    """Les clés de planification du `.env`, tirées de `planification` de la configuration. SANS défaut :
    une tâche absente, une valeur manquante, un filet sans sa mesure → ARRÊT qui nomme la clé.

    Le filet déclaré doit correspondre à un cron RÉELLEMENT présent dans le workflow (le seul qu'on sache
    lire) : un filet sans cron serait une borne sur un déclencheur qui n'existe pas."""
    pl = c.get("planification")
    if not isinstance(pl, dict) or set(pl) != set(TACHES_B):
        raise PreparerError(f"ARRÊT : `planification` doit déclarer exactement {sorted(TACHES_B)} "
                            f"(lu : {sorted(pl) if isinstance(pl, dict) else pl}).")
    out = []
    for t, cle in TACHES_B.items():
        d = pl[t]
        if d.get("non_planifiee"):
            if not d.get("pourquoi"):
                raise PreparerError(f"ARRÊT : « {t} » non planifiée sans `pourquoi` : ce silence doit se justifier.")
            out.append((f"SPINDEX_VEILLEUR_PERIODE_{cle}_S", "non-planifiée"))
            continue
        for k in ("periode_s", "precision_s", "delai_aleatoire_s", "declencheur"):
            if d.get(k) in (None, ""):
                raise PreparerError(f"ARRÊT : `planification.{t}.{k}` absent. Rien n'est deviné.")
        out += [(f"SPINDEX_VEILLEUR_PERIODE_{cle}_S", int(d["periode_s"])),
                (f"SPINDEX_VEILLEUR_PRECISION_{cle}_S", int(d["precision_s"])),
                (f"SPINDEX_VEILLEUR_DELAI_ALEATOIRE_{cle}_S", int(d["delai_aleatoire_s"])),
                (f"SPINDEX_VEILLEUR_DECLENCHEUR_{cle}", d["declencheur"])]
        if d.get("filet_s") is not None or d.get("filet_source"):
            if not (d.get("filet_s") and d.get("filet_source")):
                raise PreparerError(f"ARRÊT : `planification.{t}` : filet_s et filet_source vont ensemble.")
            if t == "passe":
                periode_du_cron()            # le filet existe : exactement un cron lisible dans le workflow
            out += [(f"SPINDEX_VEILLEUR_FILET_{cle}_S", int(d["filet_s"])),
                    (f"SPINDEX_VEILLEUR_FILET_{cle}_SOURCE", d["filet_source"])]
    return out


def preparer(config_path, etat_dir, reprise="incrémental"):
    with open(config_path, encoding="utf-8") as fh:
        c = json.load(fh)
    for k in ("chain_id", "rewards", "deploy_block", "tx_deploiement", "multicall3", "tables_base_url"):
        if c.get(k) in (None, ""):
            raise PreparerError(f"ARRÊT : {config_path} ne porte pas « {k} ». Rien n'est deviné.")

    # LE LOT PUBLIÉ EMBARQUÉ, et pas l'arbre `contracts/`. Sans cette ligne, `Settings.contracts_dir`
    # retombe sur `<paquet>/../../contracts`, c'est-à-dire, depuis ce dépôt, `~/stockslot/contracts` :
    # sur la machine du keeper ça EXISTE et tout marche, sur le runner GitHub ça n'existe pas et la
    # passe meurt en `exception:ArtefactError`. Trouvé par le banc rejoué depuis un clone frais — le
    # banc lancé dans l'arbre d'origine ne pouvait pas le voir, il avait le vrai `contracts/` à côté.
    # Le lot embarqué porte les mêmes contrôles (empreintes épinglées au manifeste, keccak de la
    # source confronté à celui que l'ABI déclare) : c'est ce qui rend le veilleur autonome.
    contrats = os.path.join(ICI, "veilleur", "public")
    if not os.path.exists(os.path.join(contrats, "MANIFESTE.json")):
        raise PreparerError(
            f"ARRÊT : lot d'artefacts embarqué absent ({contrats}/MANIFESTE.json). Sans lui, le paquet "
            f"irait chercher un arbre `contracts/` qui n'existe pas sur un runner — et, pire, qui "
            f"existe sur la machine du keeper : le défaut ne se verrait qu'en production.")

    env_path = os.path.join(etat_dir, "veilleur-b.env")
    cle_path = os.path.join(etat_dir, "attest-b.hex")
    pub_path = os.path.join(etat_dir, "attest-b.pub")

    poser_cle(cle_path, _secret("SPINDEX_B_ATTEST_KEY_HEX"))
    url = _secret("SPINDEX_B_RPC_URL")
    profil = profil_rpc(url, c.get("rpc_profil"))
    # Un fournisseur par RÔLE (arbitrage 2026-09-28) : le secret sert les JOURNAUX ; l'ÉTAT va au
    # fournisseur public déclaré dans la configuration. Sans `rpc_etat`, un seul fournisseur pour tout.
    etat = c.get("rpc_etat")
    if etat is not None:
        if not (isinstance(etat, dict) and etat.get("url") and etat.get("profil")):
            raise PreparerError(f"ARRÊT : `rpc_etat` de {config_path} doit porter `url` ET `profil`.")
        if profil is None:
            raise PreparerError("ARRÊT : fournisseurs par rôle, mais aucun profil pour les JOURNAUX "
                                "(`rpc_profil`) : un rôle ne se déclare pas à moitié.")
        profil_rpc(etat["url"], etat["profil"])          # même garde de domaine que pour le secret
        fournisseurs = [("SPINDEX_RPC_URL_JOURNAUX", url), ("SPINDEX_RPC_PROFIL_JOURNAUX", profil),
                        ("SPINDEX_RPC_URL_ETAT", etat["url"]), ("SPINDEX_RPC_PROFIL_ETAT", etat["profil"])]
    else:
        fournisseurs = [("SPINDEX_RPC_URL", url)] + ([("SPINDEX_RPC_PROFIL", profil)] if profil else [])

    ecrire_env(env_path, fournisseurs + [
        ("SPINDEX_CHAIN_ID", int(c["chain_id"])),
        ("SPINDEX_REWARDS_ADDR", c["rewards"]),
        ("SPINDEX_REWARDS_DEPLOY_BLOCK", int(c["deploy_block"])),
        ("SPINDEX_MULTICALL3", c["multicall3"]),
        ("SPINDEX_TABLES_BASE_URL", c["tables_base_url"]),
        ("SPINDEX_CONTRACTS_DIR", contrats),
        ("SPINDEX_ATTEST_KEY_FILE", cle_path),
        ("SPINDEX_ATTEST_PUBKEY_FILE", pub_path),
        ("SPINDEX_VEILLEUR_STATE_DIR", os.path.join(etat_dir, "etat")),
        ("SPINDEX_VEILLEUR_BATTEMENT_DIR", os.path.join(etat_dir, "etat")),
        ("SPINDEX_VEILLEUR_INSTANCE", "b"),
        ("SPINDEX_VEILLEUR_REPRISE", reprise),
        # Cadence de CETTE instance, DÉCLARÉE dans la configuration (`planification`), tâche par tâche.
        # Le cron du workflow n'en est PLUS l'autorité : GitHub le bride (mesuré : écarts de 127 à 471
        # min pour `*/15`), c'est le FILET. La fraîcheur vient du déclencheur externe (workflow_dispatch
        # par la surveillance) ; le silence admissible, du retard MESURÉ du filet (KE#130).
        ("SPINDEX_VEILLEUR_PLANIFICATEUR", "github-actions"),
    ] + planification_env(c) + [        ("SPINDEX_PUBLISH_DEADLINE_S", int(c.get("publish_deadline_s") or 300)),
        ("SPINDEX_WINDOW_ALERT_S", int(c.get("window_alert_s") or 720)),
        ("SPINDEX_WINDOW_NEED_S", int(c.get("window_need_s") or 480)),
        ("SPINDEX_MULTICALL_BATCH", int(c.get("multicall_batch") or 4000)),
        ("SPINDEX_WEEK_UNPOSTED_ALERT_DAYS", int(c.get("week_unposted_alert_days") or 7)),
        ("SPINDEX_DRAW_UNSETTLED_ALERT_DAYS", int(c.get("draw_unsettled_alert_days") or 3)),
    ])

    # Le `.env` est relu par L'AUDITEUR DU PAQUET SCELLÉ, pas par moi : ce qui compte est ce que voit
    # le CONSOMMATEUR (extension de KE#107 vérifiée le 2026-09-21).
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    from veilleur.config import audit_env_file
    ok, bad = audit_env_file(env_path)
    if not ok:
        lignes = "\n".join(f"  ligne {i} : {k} — {why}" for i, k, why in bad)
        raise PreparerError(f"ARRÊT : le `.env` que je viens d'écrire est refusé par l'auditeur du "
                            f"paquet scellé.\n{lignes}")

    # La clé PUBLIQUE, dérivée de la privée, posée hors de toute enveloppe : c'est l'ancre de
    # confiance locale (KE#130). Elle est publique par construction : elle peut être imprimée.
    from veilleur.attest import AttestKey
    pub = AttestKey.load(cle_path).public_hex
    with open(pub_path, "w", encoding="utf-8") as fh:
        fh.write(pub + "\n")
    return {"env": env_path, "cle_publique": pub, "etat": os.path.join(etat_dir, "etat")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--etat", required=True, help="dossier de travail de l'instance b")
    ap.add_argument("--reprise", default="incrémental", choices=("incrémental", "complet"))
    a = ap.parse_args(argv)
    try:
        rep = preparer(a.config, a.etat, a.reprise)
    except PreparerError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"configuration écrite : {rep['env']}")
    print(f"clé publique d'attestation de l'instance b : {rep['cle_publique']}")
    print("  (à comparer à celle que l'utilisateur a notée en créant la clé hors ligne — "
          "si elle diffère, le secret collé n'est pas la bonne clé)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
