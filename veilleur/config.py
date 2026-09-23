"""Configuration du veilleur : lecture de `.env`, et REFUS de tout `.env` mal cité (KE#107).

Pourquoi ce module existe au lieu d'un `os.environ` direct
----------------------------------------------------------
`source .env` est une EXÉCUTION de shell, pas une lecture de fichier. Une valeur non citée qui
contient `>` redirige (et crée un fichier PORTANT LE NOM du secret), `&` met en arrière-plan et
TRONQUE la valeur, `|` tube. C'est exactement la fuite du 2026-07-17 : 11 fichiers de 0 octet dont
le nom était un fragment d'un mot de passe, commités et poussés pendant trois mois.

Le veilleur ne se contente donc pas d'éviter le piège : il le DÉTECTE. `load_env()` refuse le
fichier entier si une seule valeur n'est pas entre apostrophes simples, et nomme les lignes
fautives — sans jamais imprimer leur valeur.

Aucun secret n'arrive par la ligne de commande : les clés se lisent dans un fichier dont le chemin
est nommé par l'environnement, jamais leur contenu.
"""
import os
import re
import sys

from .battement import PlanificationError
from .battement import planificateur as _lire_planificateur
from .battement import planification as _lire_planification
from .window_history import BESOIN_DEFAUT_S

# `KEY='valeur'` ou `export KEY='valeur'`. L'apostrophe simple est la SEULE citation acceptée :
# les guillemets doubles laissent vivre `$(...)`, `` ` ``, `$VAR`, donc ils ne ferment pas le piège.
_OK = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)='([^']*)'\s*(?:#.*)?$")
_ANY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


class ConfigError(RuntimeError):
    """Échec BRUYANT de configuration (KE#105) : jamais de valeur par défaut silencieuse."""


def audit_env_file(path):
    """Rend (ok, lignes_fautives). Ne rend JAMAIS les valeurs : seulement numéro de ligne et clé."""
    bad = []
    n_pairs = 0
    if not os.path.exists(path):
        raise ConfigError(f"ARRÊT : {path} n'existe pas. Le veilleur ne devine pas sa configuration.")
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m_any = _ANY.match(line)
            if not m_any:
                bad.append((i, "(ligne non reconnue)", "ni commentaire ni affectation"))
                continue
            n_pairs += 1
            if not _OK.match(line):
                bad.append((i, m_any.group(1), "valeur PAS entre apostrophes simples (KE#107)"))
    # Assertion de CARDINAL (KE#111) : un fichier vide passerait « sans faute » et ne prouverait rien.
    if n_pairs == 0:
        bad.append((0, "(aucune)", "le fichier ne contient AUCUNE affectation : il ne configure rien"))
    return (not bad), bad


def load_env(path=None, required=()):
    """Charge `.env` après audit. `required` : clés dont l'absence est un ARRÊT."""
    path = path or os.environ.get("SPINDEX_VEILLEUR_ENV") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".env")
    ok, bad = audit_env_file(path)
    if not ok:
        lines = "\n".join(f"  ligne {i} : {k} — {why}" for i, k, why in bad)
        raise ConfigError(
            f"ARRÊT : {path} viole la règle de citation (KE#107). Aucune valeur n'est lue.\n{lines}\n"
            "Toute valeur doit être entre apostrophes simples : KEY='valeur'.")
    env = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = _OK.match(line)
            if m:
                env[m.group(1)] = m.group(2)
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise ConfigError(f"ARRÊT : clés absentes ou vides dans {path} : {', '.join(missing)}")
    return env


class Settings:
    """Réglages du veilleur. Tout vient de `.env` ; rien n'a de valeur par défaut qui masquerait un oubli,
    SAUF les chemins internes au dépôt, qui ne sont pas des secrets."""

    REQUIRED = (
        "SPINDEX_RPC_URL",
        "SPINDEX_CHAIN_ID",
        "SPINDEX_REWARDS_ADDR",
        "SPINDEX_REWARDS_DEPLOY_BLOCK",
        "SPINDEX_MULTICALL3",
        "SPINDEX_TABLES_BASE_URL",
        "SPINDEX_ATTEST_KEY_FILE",
    )

    def __init__(self, env):
        self.rpc_url = env["SPINDEX_RPC_URL"]
        self.chain_id = int(env["SPINDEX_CHAIN_ID"])
        self.rewards = _addr(env["SPINDEX_REWARDS_ADDR"], "SPINDEX_REWARDS_ADDR")
        self.deploy_block = int(env["SPINDEX_REWARDS_DEPLOY_BLOCK"])
        self.multicall3 = _addr(env["SPINDEX_MULTICALL3"], "SPINDEX_MULTICALL3")
        self.tables_base_url = env["SPINDEX_TABLES_BASE_URL"].rstrip("/")
        self.attest_key_file = env["SPINDEX_ATTEST_KEY_FILE"]
        # ANCRE DE CONFIANCE de `vérifier` : la clé publique ATTENDUE, posée HORS de l'enveloppe.
        # Sans elle, `vérifier` authentifie la clé que le document transporte, c'est-à-dire rien
        # (KE#130). Elle n'est pas dans REQUIRED : un signataire du Safe la donne en ligne de
        # commande (`--clé-publique`) et n'a pas notre `.env`. Absente des deux côtés, `vérifier`
        # REFUSE — il ne se rabat jamais sur la clé de l'enveloppe.
        self.attest_pubkey_file = env.get("SPINDEX_ATTEST_PUBKEY_FILE") or None
        self.state_dir = env.get("SPINDEX_VEILLEUR_STATE_DIR") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "etat")
        self.contracts_dir = env.get("SPINDEX_CONTRACTS_DIR") or os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "contracts"))
        # Règle de TEMPS de l'arbitrage Q2 : la table doit arriver dans les 8 min du bloc d'instantané,
        # et la fenêtre d'état MESURÉE doit rester au-dessus de 12 min. Les deux sont des paramètres de
        # SÛRETÉ tirés d'une mesure : ils vivent dans `.env` pour être relevés sans toucher au code.
        # 5 minutes (et non 8) : resserré par le coordinateur une fois la fenêtre réellement mesurée
        # à 10,4 min. C'est une CONSIGNE d'exploitation ; la borne qui décide, elle, est DÉRIVÉE
        # (`DureeHistory.delai_max_admis` : fenêtre mesurée − 3 × durée de vérification observée).
        self.publish_deadline_s = int(env.get("SPINDEX_PUBLISH_DEADLINE_S") or 300)
        self.window_alert_s = int(env.get("SPINDEX_WINDOW_ALERT_S") or 720)
        # BESOIN de sûreté que la fenêtre d'état doit couvrir : la règle des 8 minutes de publication
        # (arbitrage Q2-3, ATELIERS.md §Q2 point 3). La GRAVITÉ des alertes de fenêtre se juge contre lui
        # (window_history.py), jamais contre un record relevé sur le nœud le plus généreux (KE#133).
        self.window_need_s = int(env.get("SPINDEX_WINDOW_NEED_S") or BESOIN_DEFAUT_S)
        verifier_besoin(self.window_need_s, self.publish_deadline_s, self.window_alert_s)
        self.max_multicall_batch = int(env.get("SPINDEX_MULTICALL_BATCH") or 4000)
        # Repli de sonde tant que SPINDEX n'est pas déployé : la fenêtre se mesure alors sur une
        # cible tierce de MÊME FORME, et le rapport le dit (jamais un chiffre sans sa provenance).
        self.window_probe_to = env.get("SPINDEX_WINDOW_PROBE_TO") or None
        self.window_probe_data = env.get("SPINDEX_WINDOW_PROBE_DATA") or "0x18160ddd"
        # Surveillance à mèche longue : seuils d'alerte, bien en amont des J+90 / J+30 du contrat.
        self.week_unposted_alert_days = int(env.get("SPINDEX_WEEK_UNPOSTED_ALERT_DAYS") or 7)
        self.draw_unsettled_alert_days = int(env.get("SPINDEX_DRAW_UNSETTLED_ALERT_DAYS") or 3)
        # Lecture des journaux : `incrémental` (point de reprise figé jusqu'à `finalized`, vérifié par
        # hash à chaque passe) pour NOTRE service ; `complet` (depuis le bloc de déploiement, sans
        # cache) est la référence, celle du vérificateur public et du contrôle différentiel.
        self.reprise = env.get("SPINDEX_VEILLEUR_REPRISE") or "incrémental"
        if self.reprise not in ("incrémental", "complet"):
            raise ConfigError(f"ARRÊT : SPINDEX_VEILLEUR_REPRISE vaut « {self.reprise} », attendu "
                              f"« incrémental » ou « complet ».")
        # Instance (« a » ou « b », BATTEMENT.md) : la seconde tourne sur une infrastructure
        # INDÉPENDANTE. Rien ici ne suppose que les deux partagent une machine ou un disque.
        self.instance = env.get("SPINDEX_VEILLEUR_INSTANCE") or None
        if self.instance not in (None, "a", "b"):
            raise ConfigError(f"ARRÊT : SPINDEX_VEILLEUR_INSTANCE vaut « {self.instance} », attendu a ou b.")
        # CADENCE DE L'INSTANCE — obligatoire, sans défaut (KE#73). `a` bat toutes les 5 min sous systemd,
        # `b` toutes les 15 min sur GitHub Actions ; une constante du paquet ferait publier à `b` la borne
        # de `a`, et la surveillance la déclarerait muette à chaque passage. Une clé absente est un ARRÊT
        # qui la NOMME : le service refuse de démarrer plutôt que de deviner sa propre cadence.
        try:
            self.planificateur = _lire_planificateur(env)
            self.planification = _lire_planification(env)
        except PlanificationError as e:
            # Même chemin de refus que toute autre configuration absente : message NOMMÉ, code 2, et le
            # battement porte `configuration` (le message dit quelle clé manque).
            raise ConfigError(str(e)) from e
        # Dossier des battements (un fichier PAR TÂCHE, BATTEMENT.md v1.2) et de health.json.
        self.battement_dir = env.get("SPINDEX_VEILLEUR_BATTEMENT_DIR") or self.state_dir

    @classmethod
    def load(cls, path=None):
        return cls(load_env(path, required=cls.REQUIRED))


def verifier_besoin(besoin_s, publish_deadline_s, window_alert_s):
    """Cohérence des trois réglages de temps. Un besoin sous la consigne de publication serait un besoin
    faux (la consigne publie plus tard que ce que la fenêtre est censée couvrir) ; un seuil de consigne
    sous le besoin rendrait l'avertissement permanent muet dans la zone où la fenêtre ne couvre plus
    la règle."""
    if besoin_s <= 0:
        raise ConfigError(f"ARRÊT : SPINDEX_WINDOW_NEED_S vaut {besoin_s} s, attendu > 0.")
    if besoin_s < publish_deadline_s:
        raise ConfigError(f"ARRÊT : besoin de fenêtre {besoin_s} s < consigne de publication "
                          f"{publish_deadline_s} s : la fenêtre ne couvrirait pas la consigne elle-même.")
    if window_alert_s < besoin_s:
        raise ConfigError(f"ARRÊT : seuil d'alerte de fenêtre {window_alert_s} s < besoin {besoin_s} s : "
                          f"l'avertissement permanent se tairait sous le besoin.")


def _addr(v, key):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", v or ""):
        raise ConfigError(f"ARRÊT : {key} n'est pas une adresse 0x + 40 hexa.")
    return v.lower()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    p = target or os.environ.get("SPINDEX_VEILLEUR_ENV") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".env")
    ok, bad = audit_env_file(p)
    if ok:
        print(f"OK : {p} — toutes les valeurs sont entre apostrophes simples (KE#107).")
        sys.exit(0)
    print(f"ÉCHEC : {p}", file=sys.stderr)
    for i, k, why in bad:
        print(f"  ligne {i} : {k} — {why}", file=sys.stderr)
    sys.exit(1)
