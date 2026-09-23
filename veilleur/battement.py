"""Battement du veilleur — contrat commun `backend/BATTEMENT.md`, à la lettre.

Réécrit à la FIN de chaque passe planifiée, y compris une passe en échec, atomiquement (`.tmp` +
`fsync` + `os.replace`, KE#112). Trois interdits du contrat, et comment ils sont tenus ici :

- **écrire AVANT la passe** (il battrait pendant qu'elle est bloquée, KE#131) : l'unique appel à
  `ecrire()` est placé APRÈS le travail, dans `__main__.passe` ; aucun fil séparé ;
- **sauter le battement sur échec** : l'échec est capturé, puis le battement est écrit avec
  `resultat: "erreur"` et un `code` ; une configuration illisible elle-même produit un battement
  (le chemin vient alors de la ligne de commande de l'unité, pas du `.env`) ;
- **`ok` sur une passe qui n'a rien pu lire** : refusé ici même, `bloc` nul impose `erreur`.

Le compteur `passe` est repris du fichier au démarrage (le service est un `oneshot` relancé par un
timer : chaque passe est un nouveau processus) et n'est JAMAIS remis à zéro.
"""
import hashlib
import json
import os
import time

FORMAT = 1
SERVICE = "veilleur"
INSTANCES = ("a", "b")
RESULTATS = ("ok", "refus", "erreur")
_ICI = os.path.dirname(os.path.abspath(__file__))


class BattementError(RuntimeError):
    pass


def empreinte_sources(racine=_ICI):
    """sha256 des sources EN SERVICE : les `*.py` du paquet (hors banc), chemin relatif + contenu."""
    h = hashlib.sha256()
    fichiers = sorted(f for f in os.listdir(racine) if f.endswith(".py"))
    if not fichiers:
        raise BattementError("ARRÊT : aucune source à empreinter (KE#111).")
    for f in fichiers:
        h.update(f.encode() + b"\0")
        with open(os.path.join(racine, f), "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()


# Tâches du veilleur, et leur planification — la MÊME que celle des timers de `systemd/` (un test la relit
# PAR SYSTEMD, `systemd-analyze calendar`, et exige l'égalité : une dérive entre ce tableau et les unités
# fausserait silencieusement les `silence_max_s` exposés).
TACHES = {
    "passe": {"unité": "spindex-veilleur@.timer", "période_s": 300, "précision_s": 10,
              "délai_aléatoire_s": 0},
    "differentiel-quotidien": {"unité": "spindex-veilleur-differentiel-quotidien@.timer",
                               "période_s": 86_400, "précision_s": 60, "délai_aléatoire_s": 1800},
    "differentiel-complet": {"unité": "spindex-veilleur-differentiel@.timer",
                             "période_s": 604_800, "précision_s": 60, "délai_aléatoire_s": 1800},
}

# Mesures qui fondent la borne THÉORIQUE du pire cas, quand aucune durée n'a encore été observée.
# Provenance : rapports/veilleur-exploitation.md §1 (banc 2026-09-21 ; RPC 4663 mesuré 2026-09-21 21:02Z).
APPELS_PASSE_A_CHAUD = 64            # mesuré sur banc, indépendant de l'âge du contrat
LATENCE_MAX_S = 1.89                 # max mesuré, eth_getLogs 1 000 blocs sur un contrat ACTIF
CADENCE_MAX_BLOCS_S = 9.98           # max des 3 mesures du 2026-09-21 (rapport veilleur §3)
BLOCS_PAR_APPEL = 1000


class Battement:
    """Un fichier PAR TÂCHE (`battement-<tache>.json`, BATTEMENT.md v1.1/v1.2)."""

    def __init__(self, dossier, instance, tache):
        if instance not in INSTANCES:
            raise BattementError(f"ARRÊT : instance « {instance} » inconnue, attendu {INSTANCES}.")
        if tache not in TACHES:
            raise BattementError(f"ARRÊT : tâche « {tache} » inconnue, attendu {sorted(TACHES)}.")
        self.dossier = dossier
        self.path = os.path.join(dossier, f"battement-{tache}.json")
        self.instance = instance
        self.tache = tache
        self.precedent = 0
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError) as e:
                raise BattementError(f"ARRÊT : battement existant illisible ({e}) : le compteur ne "
                                     f"peut pas être repris, et une remise à zéro ne se confond "
                                     f"pas avec un redémarrage — à examiner.") from e
            # Seule l'INSTANCE est contrôlée ici : la tâche est dans le NOM du fichier, un contrôle du
            # champ `tache` serait inatteignable (garde décorative, KE#129 — retirée après l'avoir vue).
            if doc.get("instance") != instance:
                raise BattementError(
                    f"ARRÊT : {self.path} appartient à l'instance « {doc.get('instance')} », pas à "
                    f"« {instance} ». Deux instances sur le MÊME battement se masqueraient l'une l'autre : "
                    f"l'une pourrait être morte sans que rien ne le montre.")
            self.precedent = int(doc.get("passe") or 0)

    def ecrire(self, resultat, code=None, detail=None, bloc=None, rpc=None):
        if resultat not in RESULTATS:
            raise BattementError(f"ARRÊT : résultat « {resultat} » hors contrat {RESULTATS}.")
        if resultat == "ok" and bloc is None:
            # Interdit du contrat : « ok » veut dire « la passe a fait son travail ».
            resultat, code = "erreur", "aucune_lecture"
            detail = detail or "passe déclarée ok sans aucun bloc lu : requalifiée en erreur."
        if resultat == "ok":
            code = None
        elif not code:
            raise BattementError("ARRÊT : un refus ou une erreur sans code n'est pas diagnosticable.")
        if bloc is None and not detail:
            detail = "la passe n'a pas pu lire la chaîne"
        rpc = rpc or {}
        doc = {
            "format": FORMAT,
            "service": SERVICE,
            "instance": self.instance,
            "tache": self.tache,
            "ts": int(time.time()),
            "passe": self.precedent + 1,
            "bloc": bloc,
            "resultat": resultat,
            "code": code,
            "detail": detail,
            "empreinte": empreinte_sources(),
            # Arbitrage Q4 : les 429 sont COMPTÉS et exposés. Un nœud qui nous freine est un signal.
            "rpc": {"appels": int(rpc.get("calls", 0)), "http_429": int(rpc.get("http_429", 0)),
                    "attente_429_s": float(rpc.get("attente_429_s", 0.0)),
                    "plages_découpées": int(rpc.get("plages_découpées", 0))},
        }
        _ecrire_json(self.path, doc)
        self.precedent += 1
        return doc


def _ecrire_json(path, doc):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------- durées et health.json

def enregistrer_duree(dossier, tache, duree_s, garder=200):
    """Durée de CHAQUE exécution, réussie ou non : une passe qui s'enlise jusqu'à l'erreur est
    précisément le pire cas qu'on doit connaître."""
    p = os.path.join(dossier, "durees.json")
    d = {}
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    d.setdefault(tache, []).append(round(float(duree_s), 3))
    d[tache] = d[tache][-garder:]
    _ecrire_json(p, d)
    return d


def pire_cas(tache, observees, tete=None, deploiement=None, cadence=CADENCE_MAX_BLOCS_S):
    """Pire cas d'une exécution : max(borne THÉORIQUE, max OBSERVÉ). Rend (secondes, provenance).

    La borne théorique vient des mesures (appels × latence max) ; l'observé la relève si la réalité est
    pire. Jamais la moyenne : une borne de sûreté tirée d'une moyenne se fait battre une fois sur deux.
    """
    if tache == "passe":
        appels = APPELS_PASSE_A_CHAUD
    elif tache == "differentiel-quotidien":
        from .journaux import MARGE_QUOTIDIENNE
        appels = APPELS_PASSE_A_CHAUD + (86_400 * cadence + MARGE_QUOTIDIENNE) / BLOCS_PAR_APPEL
    else:
        if tete is None or deploiement is None:
            appels = None
        else:
            appels = APPELS_PASSE_A_CHAUD + (tete - deploiement) / BLOCS_PAR_APPEL
    theorique = None if appels is None else appels * LATENCE_MAX_S
    obs = max(observees) if observees else None
    candidats = [x for x in (theorique, obs) if x is not None]
    if not candidats:
        return None, "NON DÉRIVABLE : ni borne théorique (âge du contrat inconnu) ni durée observée"
    v = max(candidats)
    src = ("max observé" if obs is not None and v == obs else "borne théorique") + \
          f" (théorique {None if theorique is None else round(theorique, 1)} s = " \
          f"{None if appels is None else round(appels)} appels × {LATENCE_MAX_S} s ; " \
          f"observé max {obs} s sur {len(observees)} exécution(s))"
    return round(v, 1), src


def derive(tache, pire_s, cadence=CADENCE_MAX_BLOCS_S):
    """`silence_max_s` et retard de bloc admissible, DÉRIVÉS (BATTEMENT.md v1.2, lectures 1 et 3).

    Silence : entre deux fins d'exécution, au plus une période + la précision et le délai aléatoire du
    timer + la durée de l'exécution suivante ; si le pire cas dépasse la période, systemd saute le
    déclenchement suivant (unité encore active) : on ajoute une période par dépassement.
    Retard : `bloc` est la tête lue au DÉBUT de l'exécution ; la surveillance peut lire jusqu'à
    `silence_max_s` après la fin, donc au plus `pire + silence_max` secondes plus tard, à la cadence max.
    """
    t = TACHES[tache]
    if pire_s is None:
        return None, None
    per = t["période_s"]
    silence = per + t["précision_s"] + t["délai_aléatoire_s"] + pire_s
    silence += per * int(pire_s // per)
    retard = int(-(-((pire_s + silence) * cadence) // 1))
    return int(-(-silence // 1)), retard


def ecrire_health(dossier, instance, tete=None, deploiement=None, cadence=None):
    """`health.json` : ce que la surveillance lit pour ne rien choisir elle-même (v1.2)."""
    p = os.path.join(dossier, "durees.json")
    durees = {}
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            durees = json.load(fh)
    cad = cadence if cadence and cadence > CADENCE_MAX_BLOCS_S else CADENCE_MAX_BLOCS_S
    taches = {}
    for nom, t in TACHES.items():
        pire, src = pire_cas(nom, durees.get(nom, []), tete, deploiement, cad)
        silence, retard = derive(nom, pire, cad)
        taches[nom] = {
            "fichier": f"battement-{nom}.json", "timer": t["unité"], "période_s": t["période_s"],
            "pire_exécution_s": pire, "pire_exécution_source": src,
            "silence_max_s": silence, "retard_bloc_max": retard,
            "formules": {"silence_max_s": "période + précision + délai_aléatoire + pire "
                                          "(+ une période par dépassement de la période)",
                         "retard_bloc_max": "ceil((pire + silence_max_s) × cadence_max)"},
        }
    doc = {"format": 1, "service": SERVICE, "instance": instance, "ts": int(time.time()),
           "empreinte": empreinte_sources(),
           "cadence_blocs_s": {"valeur": cad, "source": "max(mesure de la passe, 9,98 mesuré le 2026-09-21)"},
           "taches": taches}
    _ecrire_json(os.path.join(dossier, "health.json"), doc)
    return doc


def qualifier_differentiel(res):
    etat = res.get("état")
    if etat == "IDENTIQUE":
        return "ok", None, res.get("vacuité")
    if etat == "DIVERGENT":
        return "refus", "differentiel_divergent", res.get("motif")
    return "refus", "differentiel_" + str(etat).lower(), res.get("motif")


def qualifier(rapport):
    """(resultat, code, detail) d'une passe de surveillance, selon BATTEMENT.md.

    `erreur` = la passe n'a PAS fait son travail (section en échec) ; `refus` = elle l'a fait et a trouvé une
    alerte MÉTIER (P0, puis P1) ; `ok` sinon. Depuis l'arbitrage du 2026-09-22, le code de sortie ne porte plus
    les alertes métier : elles ne vivent QUE dans le battement — une P1 absente d'ici serait donc muette
    (KE#105), d'où `alerte_P1`. Une INFO nommée (déploiement sans semaine) est rendue dans `detail`.
    """
    echecs = rapport.get("sections_en_échec") or []
    if echecs:
        return "erreur", "section_en_echec:" + echecs[0], "sections en échec : " + ", ".join(echecs)
    alertes = rapport.get("alertes", [])
    for g in ("P0", "P1"):
        cles = [a.get("clé") or a.get("source") for a in alertes if a.get("gravité") == g]
        if cles:
            return "refus", "alerte_" + g, g + " : " + ", ".join(str(x) for x in cles[:8])
    # P2 (ex. `fenêtre_recul_sans_risque`) : la passe reste `ok` — ce n'est pas un refus — mais ses clés sont
    # NOMMÉES dans `detail`, pour qu'un P2 ne vive pas seulement dans un rapport que personne ne lit (KE#105).
    p2 = [str(a.get("clé") or a.get("source")) for a in alertes if a.get("gravité") == "P2"]
    p2 = ("P2 : " + ", ".join(p2[:8])) if p2 else None
    car = rapport.get("compte_à_rebours") or {}
    if car.get("état") == "AUCUNE_SEMAINE_DEPUIS_LE_DÉPLOIEMENT":
        info = "INFO : " + str(car.get("explication"))[:380]
        return "ok", None, (p2 + " ; " + info) if p2 else info
    return "ok", None, p2


def sortie_de(doc):
    """Code de sortie d'une tâche planifiée, DÉRIVÉ du battement ÉCRIT — jamais calculé à côté.

    La sortie dit la SANTÉ de la tâche (a-t-elle fait son travail ?), pas l'existence d'alertes métier : `ok` et
    `refus` sortent 0 ; `erreur` sort 20 si une section n'a pu être vérifiée (INDISPONIBLE), 2 sinon
    (configuration, chaîne inattendue, amorçage absent, RPC, exception). Dérivée du document écrit, elle suit
    aussi les requalifications faites par `ecrire` (`ok` sans bloc lu → `erreur`) : exit et battement ne
    peuvent pas se contredire.
    """
    if doc["resultat"] != "erreur":
        return 0
    return 20 if str(doc.get("code") or "").startswith("section_en_echec") else 2
