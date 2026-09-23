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


# Tâches du veilleur. Leur PLANIFICATION n'est PAS ici : elle est propre à l'INSTANCE.
#
# Pourquoi (défaut mesuré le 2026-09-23) : `période_s` valait 300 EN DUR — la cadence du timer systemd de
# l'instance `a`. L'instance `b` tourne sur GitHub Actions toutes les 15 minutes ; elle publiait donc un
# `silence_max_s` de 431 s et la surveillance l'aurait déclarée MUETTE à chaque passage. Élargir la borne
# aurait fait taire une alerte VRAIE pour un service lent (KE#121) : la période est une donnée de
# CONFIGURATION de l'instance, et `silence_max_s` en dérive par la formule inchangée.
#
# `unité` reste ici : c'est le nom du timer systemd de RÉFÉRENCE, celui que `systemd/` livre et qu'un test
# relit PAR SYSTEMD (`systemd-analyze calendar`) pour vérifier qu'il tient bien la période que `.env.exemple`
# déclare pour `a`. Une instance qui n'est pas lancée par systemd (GitHub Actions) ne le publie pas.
TACHES = {
    "passe": {"unité": "spindex-veilleur@.timer", "clé": "PASSE"},
    "differentiel-quotidien": {"unité": "spindex-veilleur-differentiel-quotidien@.timer",
                               "clé": "DIFFERENTIEL_QUOTIDIEN"},
    "differentiel-complet": {"unité": "spindex-veilleur-differentiel@.timer",
                             "clé": "DIFFERENTIEL_COMPLET"},
}

# Valeur qui déclare, EXPLICITEMENT, qu'une tâche n'est pas planifiée sur cette instance (l'instance `b`
# ne lance ses différentiels qu'à la main). Ce n'est pas un silence : `health.json` publie alors
# `planifiée: false` et `silence_max_s: null`, et la surveillance a de quoi distinguer « je n'ai pas de
# cadence » de « je n'ai pas pu dériver ma borne » (KE#105).
NON_PLANIFIEE = "non-planifiée"

PLANIFICATEURS = ("systemd", "github-actions")


class PlanificationError(BattementError):
    """Planification d'instance absente, incomplète ou hors domaine. Jamais de valeur par défaut (KE#73)."""


def cles_planification(tache):
    """Les trois clés `.env` qui déclarent la planification de `tache` sur CETTE instance."""
    c = TACHES[tache]["clé"]
    return (f"SPINDEX_VEILLEUR_PERIODE_{c}_S", f"SPINDEX_VEILLEUR_PRECISION_{c}_S",
            f"SPINDEX_VEILLEUR_DELAI_ALEATOIRE_{c}_S")


def _entier(env, cle, minimum):
    v = (env.get(cle) or "").strip()
    if not v:
        raise PlanificationError(_MANQUE.format(cle=cle))
    try:
        n = int(v)
    except ValueError:
        raise PlanificationError(f"ARRÊT : {cle} n'est pas un entier de secondes. Une planification "
                                 f"illisible ne se remplace pas par une valeur choisie.") from None
    if n < minimum:
        raise PlanificationError(f"ARRÊT : {cle} vaut {n}, attendu ≥ {minimum}. Une période nulle ou "
                                 f"négative rendrait un `silence_max_s` que rien ne peut tenir.")
    return n


_MANQUE = ("ARRÊT : {cle} n'est pas déclarée. La cadence d'une instance est une donnée de CONFIGURATION, "
           "pas une constante du paquet : l'instance `a` bat toutes les 5 min sous systemd, l'instance `b` "
           "toutes les 15 min sur GitHub Actions. Déclarer la valeur en secondes dans le `.env` de CETTE "
           "instance (voir `.env.exemple`), ou « " + NON_PLANIFIEE + " » si la tâche n'est pas planifiée ici.")


def planification(env):
    """Planification DÉCLARÉE par l'instance : une entrée par tâche, lue dans son `.env`.

    Aucun défaut silencieux (KE#73) : une clé absente est un ARRÊT qui NOMME la clé manquante, et
    l'instance refuse de démarrer. Le cardinal est vérifié : une planification qui ne couvrirait pas
    toutes les tâches passerait « sans faute » sans rien déclarer (KE#111).
    """
    plan = {}
    for tache in TACHES:
        kper, kacc, krnd = cles_planification(tache)
        brut = (env.get(kper) or "").strip()
        if brut == NON_PLANIFIEE:
            plan[tache] = {"planifiée": False, "période_s": None, "précision_s": None,
                           "délai_aléatoire_s": None,
                           "source": f"{kper}={NON_PLANIFIEE} (déclarée non planifiée sur cette instance)"}
            continue
        # Pas de contrôle d'absence ici : `_entier` porte le refus et NOMME la clé. Un second contrôle
        # au-dessus ne pourrait jamais rougir sous cassure — il aurait l'air d'une garde et n'en serait
        # pas une (KE#129). Trouvé en exerçant le harnais : la cassure de cette ligne restait VERTE.
        plan[tache] = {"planifiée": True,
                       "période_s": _entier(env, kper, 1),
                       "précision_s": _entier(env, kacc, 0),
                       "délai_aléatoire_s": _entier(env, krnd, 0),
                       "source": f"déclarée par {kper} / {kacc} / {krnd} dans le .env de l'instance"}
    if set(plan) != set(TACHES):                    # cardinal (KE#111)
        raise PlanificationError(f"ARRÊT : planification incomplète, {sorted(set(TACHES) - set(plan))} "
                                 f"sans déclaration.")
    return plan


def planificateur(env):
    """Qui déclenche cette instance. Déclaré, jamais deviné : `a` est lancée par systemd, `b` par GitHub."""
    v = (env.get("SPINDEX_VEILLEUR_PLANIFICATEUR") or "").strip()
    if v not in PLANIFICATEURS:
        raise PlanificationError(f"ARRÊT : SPINDEX_VEILLEUR_PLANIFICATEUR vaut « {v} », attendu "
                                 f"{PLANIFICATEURS}. Ce que `health.json` publie sur le déclencheur ne "
                                 f"se devine pas depuis le paquet : les deux instances n'ont pas le même.")
    return v

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


def pire_cas(tache, observees, tete=None, deploiement=None, cadence=CADENCE_MAX_BLOCS_S, *, periode_s):
    """Pire cas d'une exécution : max(borne THÉORIQUE, max OBSERVÉ). Rend (secondes, provenance).

    La borne théorique vient des mesures (appels × latence max) ; l'observé la relève si la réalité est
    pire. Jamais la moyenne : une borne de sûreté tirée d'une moyenne se fait battre une fois sur deux.

    `periode_s` est DÉCLARÉ par l'instance et n'a pas de défaut (KE#62) : le différentiel quotidien relit
    les blocs figés DEPUIS le différentiel précédent, donc son volume est celui de SA période — 86 400 s
    en dur ici était le même défaut que `TACHES["…"]["période_s"] = 300`, à un consommateur près (KE#116).
    Une tâche non planifiée n'a pas de volume prévisible : sa borne théorique n'est pas dérivable, et
    seul l'observé parle.
    """
    if tache == "passe":
        appels = APPELS_PASSE_A_CHAUD
    elif tache == "differentiel-quotidien":
        from .journaux import MARGE_QUOTIDIENNE
        appels = None if periode_s is None else (
            APPELS_PASSE_A_CHAUD + (periode_s * cadence + MARGE_QUOTIDIENNE) / BLOCS_PAR_APPEL)
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


def derive(tache, pire_s, cadence=CADENCE_MAX_BLOCS_S, *, plan_tache):
    """`silence_max_s` et retard de bloc admissible, DÉRIVÉS (BATTEMENT.md v1.2, lectures 1 et 3).

    Silence : entre deux fins d'exécution, au plus une période + la précision et le délai aléatoire du
    timer + la durée de l'exécution suivante ; si le pire cas dépasse la période, le planificateur saute
    le déclenchement suivant (systemd : unité encore active ; GitHub Actions : `concurrency` sans
    annulation) : on ajoute une période par dépassement. FORMULE INCHANGÉE — seules les trois valeurs
    viennent désormais de la DÉCLARATION de l'instance (`plan_tache`) et non d'une constante du paquet.
    Retard : `bloc` est la tête lue au DÉBUT de l'exécution ; la surveillance peut lire jusqu'à
    `silence_max_s` après la fin, donc au plus `pire + silence_max` secondes plus tard, à la cadence max.
    Une tâche déclarée NON PLANIFIÉE ne rend aucune borne : il n'y a pas de silence à borner, et un
    nombre choisi ici serait une borne inventée.
    """
    if tache not in TACHES:
        raise BattementError(f"ARRÊT : tâche « {tache} » inconnue, attendu {sorted(TACHES)}.")
    if pire_s is None or not plan_tache["planifiée"]:
        return None, None
    per = plan_tache["période_s"]
    silence = per + plan_tache["précision_s"] + plan_tache["délai_aléatoire_s"] + pire_s
    silence += per * int(pire_s // per)
    retard = int(-(-((pire_s + silence) * cadence) // 1))
    return int(-(-silence // 1)), retard


def ecrire_health(dossier, instance, tete=None, deploiement=None, cadence=None, *,
                  planification, planificateur):
    """`health.json` : ce que la surveillance lit pour ne rien choisir elle-même (v1.2).

    `planification` et `planificateur` sont OBLIGATOIRES et sans défaut (KE#62) : ils viennent du `.env`
    de l'instance. Une valeur par défaut ici ré-introduirait exactement le défaut corrigé — la cadence de
    `a` publiée par `b`. L'ancienne forme d'appel (`ecrire_health(dossier, instance)`) lève `TypeError`,
    et un test le vérifie.
    """
    p = os.path.join(dossier, "durees.json")
    durees = {}
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            durees = json.load(fh)
    cad = cadence if cadence and cadence > CADENCE_MAX_BLOCS_S else CADENCE_MAX_BLOCS_S
    if set(planification) != set(TACHES):           # cardinal (KE#111) : une entrée par tâche, ni plus ni moins
        raise PlanificationError(f"ARRÊT : la planification déclarée couvre {sorted(planification)}, "
                                 f"attendu {sorted(TACHES)}.")
    taches = {}
    for nom, t in TACHES.items():
        pl = planification[nom]
        pire, src = pire_cas(nom, durees.get(nom, []), tete, deploiement, cad,
                             periode_s=pl["période_s"])
        silence, retard = derive(nom, pire, cad, plan_tache=pl)
        taches[nom] = {
            "fichier": f"battement-{nom}.json",
            # Le nom du timer n'est publié que par une instance RÉELLEMENT lancée par systemd : `b`
            # tourne sur GitHub Actions et publier « spindex-veilleur@.timer » y serait un mensonge.
            "timer": t["unité"] if planificateur == "systemd" else None,
            "planificateur": planificateur,
            "planifiée": pl["planifiée"],
            "période_s": pl["période_s"], "précision_s": pl["précision_s"],
            "délai_aléatoire_s": pl["délai_aléatoire_s"],
            # Une DÉCLARATION, pas une mesure : la surveillance doit la recouper avec les battements
            # réellement observés (`passe` et `ts`), sinon une instance qui annonce 15 min et bat toutes
            # les heures s'achète son propre silence (KE#130 : la borne ne vient pas du sujet contrôlé).
            "période_provenance": "DÉCLARÉE par l'instance — " + pl["source"],
            "pire_exécution_s": pire, "pire_exécution_source": src,
            "silence_max_s": silence, "retard_bloc_max": retard,
            "formules": {"silence_max_s": "période + précision + délai_aléatoire + pire "
                                          "(+ une période par dépassement de la période)",
                         "retard_bloc_max": "ceil((pire + silence_max_s) × cadence_max)"},
        }
    doc = {"format": 1, "service": SERVICE, "instance": instance, "ts": int(time.time()),
           "empreinte": empreinte_sources(), "planificateur": planificateur,
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
