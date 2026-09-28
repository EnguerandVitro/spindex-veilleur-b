"""Ce que chaque fournisseur RPC fait RÉELLEMENT — table MESURÉE, jamais devinée.

Pourquoi ce module existe
-------------------------
Le veilleur a tourné trois jours contre UN fournisseur, et tout ce que ce fournisseur fait est
devenu une hypothèse tacite du code. Le jour où le second veilleur (`b`) a été basculé sur un
fournisseur INDÉPENDANT — condition pour que l'accord entre `a` et `b` prouve quelque chose — sa
passe est tombée en `section_en_echec:lecture` sur des refus que le code ne savait pas lire.

Deux causes, mesurées le 2026-09-24 sur la chaîne 46630 :

  1. dRPC refuse les plages de journaux avec le message
     ``ranges over 10000 blocks are not supported on free plan`` (code 35), servi dans un corps
     **HTTP 400**. L'ancienne reconnaissance était une expression régulière écrite de mémoire :
     elle ne connaissait pas cette formulation, et le client a conclu « erreur non liée à la taille
     de plage : pas de découpage ». Il avait raison de ne pas deviner — il avait tort de ne pas
     savoir.
  2. Ce message MENT sur son seuil. Mesuré par dichotomie, trois fois de suite : dRPC accepte
     **101 blocs** (``toBlock - fromBlock <= 100``) et refuse 102, avec le même message qui parle de
     10 000. Une reconnaissance qui aurait cru le chiffre du message aurait redécoupé à 10 000 et
     échoué en boucle.

Règle de ce module
------------------
**Aucune chaîne de caractères n'est inventée.** Chaque signature ci-dessous a un champ ``exemple``
qui est le message tel qu'il est arrivé sur le réseau, et un champ ``mesuré`` qui dit d'où il vient.
La capture brute qui les fonde est ``mesures/rpc-fournisseurs-2026-09-24.json`` ; le banc la REJOUE
telle quelle à travers un vrai serveur HTTP local (KE#74 : par le vrai consommateur).

**Un message inconnu est un ARRÊT BRUYANT, jamais une supposition.** Se tromper dans un sens
(« ce n'est pas une erreur de plage ») coûte une passe en échec et un message qui nomme le remède.
Se tromper dans l'autre (« c'est sûrement une erreur de plage ») ferait redécouper la plage sur un
refus qui n'a rien à voir — c'est-à-dire multiplier les appels au moment précis où quelque chose ne
va pas. Le refus par défaut est donc « je ne sais pas », et il NOMME la chaîne à mesurer et à
déclarer ici.

**Aucun fourre-tout (KE#138).** Il n'existe pas de motif « attrape tout » dans cette table : placé
n'importe où il rendrait les signatures précises inatteignables, et une cassure les déclarerait
porteuses à tort. La conséquence assumée est qu'un fournisseur neuf doit être MESURÉ avant d'être
utilisable, et le message d'arrêt le dit.

**Pas d'ambiguïté silencieuse.** ``classer`` confronte le message à TOUTES les signatures ; si deux
signatures de CLASSES différentes matchent, c'est une erreur de la table elle-même et elle est
levée, pas arbitrée par l'ordre de lecture.
"""
import re

# ---------------------------------------------------------------------------- classes de refus

# Ce que le refus SIGNIFIE, indépendamment de qui l'a écrit. Le remède se décide sur la classe.
CLASSES = frozenset({
    "plage_trop_large",         # trop de BLOCS demandés d'un coup     -> découper
    "resultats_trop_nombreux",  # trop de JOURNAUX renvoyés            -> découper
    "filtre_adresse_exige",     # le fournisseur exige un filtre       -> ARRÊT (découper ne change rien)
    "bloc_inconnu",             # bloc futur / inexistant              -> pas d'état ici
    "etat_elague",              # état historique plus servi           -> pas d'état ici
    "debit",                    # limitation de débit                  -> ATTENDRE, jamais découper
    "entete_refuse",            # refus au niveau du frontal HTTP      -> ARRÊT (en-tête à corriger)
    "delai_fournisseur",        # le fournisseur n'a pas répondu à temps -> RELANCE BORNÉE, jamais découper
    "etat_indisponible",        # l'état n'est servi à AUCUNE profondeur -> pas d'état ici (fournisseur inapte)
})

# Les SEULES classes qui autorisent à redécouper une plage de journaux.
CLASSES_DECOUPABLES = frozenset({"plage_trop_large", "resultats_trop_nombreux"})

# Refus TRANSITOIRES du fournisseur : la même question, reposée plus tard, peut réussir. Remède :
# relance BORNÉE à attente croissante, paramétrée dans le PROFIL (`relance_transitoire`), sans défaut
# (KE#105) ; au-delà, échec BRUYANT et nommé. Ce n'est PAS une erreur de plage : la plage refusée
# faisait 101 blocs, sous la limite mesurée — redécouper multiplierait les appels sans rien réparer.
CLASSES_TRANSITOIRES = frozenset({"delai_fournisseur"})

# Classes qui signifient « cet état n'est pas lisible ici » pour la sonde de fenêtre.
CLASSES_SANS_ETAT = frozenset({"bloc_inconnu", "etat_elague", "etat_indisponible"})


class SignatureAmbigue(RuntimeError):
    """Deux signatures de classes DIFFÉRENTES reconnaissent le même message : la table est fautive."""


# ---------------------------------------------------------------------------- signatures mesurées

def _s(classe, motif, exemple, fournisseur, code, http, mesure):
    # `provenance` est un CODE, pas de la prose : c'est lui que le banc interroge pour savoir quelles
    # signatures doivent se retrouver mot pour mot dans la capture. Chercher une date dans la phrase
    # `mesuré` reviendrait à faire dépendre un contrôle de la rédaction d'un commentaire.
    provenance, phrase = mesure
    return {"classe": classe, "motif": re.compile(motif), "exemple": exemple,
            "fournisseur": fournisseur, "code": code, "http": http,
            "provenance": provenance, "mesuré": phrase}


# Code de provenance -> fichier de capture qui doit contenir l'exemple, ou None si l'exemple vient
# d'ailleurs (et la phrase dit alors d'où, et pourquoi il n'a pas été re-mesuré).
CAPTURES = {"capture-2026-09-24": "mesures/rpc-fournisseurs-2026-09-24.json",
            "capture-anvil-2026-09-28": "mesures/rpc-anvil-2026-09-28.json",
            "run-github-36469251579": "mesures/rpc-drpc-408-2026-09-28.json",
            "run-github-36475098966": "mesures/rpc-drpc-etat-2026-09-28.json",
            "atelier-0": None}

_LE_2026_09_24 = ("capture-2026-09-24",
                  "capture directe le 24 septembre 2026, chaîne 46630 "
                  "(mesures/rpc-fournisseurs-2026-09-24.json)")
_ANVIL_2026_09_28 = ("capture-anvil-2026-09-28",
                     "capture directe le 28 septembre 2026, anvil 1.8.1 neuf sur 127.0.0.1:18571, deux "
                     "hauteurs (0 et 5) x trois avances x deux méthodes "
                     "(mesures/rpc-anvil-2026-09-28.json, outils/capture_anvil.py)")
_RUN_36469251579 = ("run-github-36469251579",
                    "journal du run GitHub Actions 36469251579 (instance b sur dRPC), 2026-09-28T19:03Z, "
                    "pendant le ré-amorçage : eth_getLogs [125820242,125820342] (mesures/rpc-drpc-408-2026-09-28.json)")
_RUN_36475098966 = ("run-github-36475098966",
                    "journal du run GitHub Actions 36475098966 (instance b sur dRPC, 2026-09-28T19:53Z : "
                    "strandedBurn@125860733 et sondes de fenêtre) + mesure directe du même jour, RPC publics "
                    "sans clé (mesures/rpc-drpc-etat-2026-09-28.json)")
_ATELIER_0 = ("atelier-0",
              "atelier 0, le 21 septembre 2026 — non re-mesuré depuis : provoquer une limitation de "
              "débit exige de marteler un nœud public, ce que le veilleur ne fait pas pour se tester")

SIGNATURES = (
    # ---- trop de BLOCS demandés -------------------------------------------------------------
    # dRPC, plan gratuit. Le message parle de 10 000 ; la limite RÉELLE mesurée par dichotomie
    # (trois fois, têtes différentes) est 101 blocs acceptés, 102 refusés. Le remède est le même
    # (découper) mais le chiffre du message ne doit JAMAIS servir de borne.
    _s("plage_trop_large", r"^ranges over \d+ blocks are not supported on \w+ plan$",
       "ranges over 10000 blocks are not supported on free plan", "drpc", 35, 400, _LE_2026_09_24),
    # publicnode / allnodes : limite annoncée 50 000 blocs, et elle est exacte (100 000 refusé).
    _s("plage_trop_large", r"^exceed maximum block range: \d+$",
       "exceed maximum block range: 50000", "publicnode", -32701, 200, _LE_2026_09_24),

    # ---- trop de JOURNAUX renvoyés ----------------------------------------------------------
    # Nœud officiel (nitro). Ce n'est PAS une limite de plage : 5 000 000 de blocs passent avec un
    # filtre d'adresse. C'est le nombre de journaux qui borne. Le remède reste le découpage.
    _s("resultats_trop_nombreux", r"^logs matched by query exceeds limit of \d+$",
       "logs matched by query exceeds limit of 10000", "robinhood-officiel", -32000, 200,
       _LE_2026_09_24),

    # ---- le fournisseur EXIGE un filtre d'adresse -------------------------------------------
    # Découper ne changerait rien : refus quel que soit le nombre de blocs (mesuré à 100 comme à
    # 10 000). Classé à part exprès, pour que le découpage ne s'y déclenche pas.
    _s("filtre_adresse_exige", r"^Please specify an address in your request\b",
       "Please specify an address in your request or, to remove restrictions, order a dedicated "
       "full node here: https://www.allnodes.com/hood/host", "publicnode", -32701, 200,
       _LE_2026_09_24),

    # ---- bloc inexistant (futur, ou hauteur jamais atteinte) --------------------------------
    _s("bloc_inconnu", r"^unsupported block number \d+$",
       "unsupported block number 124728734", "robinhood-officiel", -32000, 200, _LE_2026_09_24),
    _s("bloc_inconnu", r"^header not found$",
       "header not found", "publicnode", -32000, 200, _LE_2026_09_24),
    _s("bloc_inconnu", r"^Unknown block$",
       "Unknown block", "drpc", 26, 400, _LE_2026_09_24),
    # anvil (bancs, répétition générale). La forme entière est ancrée ; seules les deux hauteurs sont
    # libres. Sans elle, le témoin de la sonde de fenêtre ne sait pas lire le NON d'anvil et la passe
    # bat `fenêtre_non_mesurée` (défaut de la répétition du 2026-09-28).
    _s("bloc_inconnu", r"^BlockOutOfRangeError: block height is \d+ but requested was \d+$",
       "BlockOutOfRangeError: block height is 5 but requested was 1005", "anvil", -32602, 200,
       _ANVIL_2026_09_28),

    # ---- l'état n'est servi à AUCUNE profondeur ----------------------------------------------
    # dRPC, plan gratuit, 2026-09-28 : `eth_call` / `eth_getBalance` / `eth_getStorageAt` à un bloc
    # NUMÉROTÉ sont refusés dès la tête et à toute profondeur mesurée (0 à 50 000 blocs, 8/8 dans la
    # capture), alors que `latest` répond. Ce n'est ni un retard (sa tête est égale ou EN AVANCE sur le
    # nœud officiel) ni un élagage à une profondeur : l'état par numéro n'est pas servi. Le message
    # (« First available state is 1 ») contredit ce qu'il fait ; on le classe par ce qu'il FAIT.
    _s("etat_indisponible", r"^Unknown state\. First available state is \d+$",
       "Unknown state. First available state is 1", "drpc", 27, 400, _RUN_36475098966),

    # ---- le fournisseur n'a pas répondu à temps (TRANSITOIRE) ---------------------------------
    # dRPC, plan gratuit, HTTP 408, code 30, sur une plage de 101 blocs (sous la limite mesurée) :
    # ce n'est pas la PLAGE qui est refusée, c'est le délai. Relance bornée, jamais de découpage.
    _s("delai_fournisseur", r"^Request timeout on the \w+ plan, please upgrade to paid plan$",
       "Request timeout on the free plan, please upgrade to paid plan", "drpc", 30, 408,
       _RUN_36469251579),

    # ---- état historique élagué --------------------------------------------------------------
    # Deux formes DISTINCTES sur la même URL, selon le nœud qui répond (KE#133) : le balayage dédié
    # de la capture a dû tirer trois profondeurs pour voir la seconde.
    _s("etat_elague", r"^historical state [0-9a-fA-F]{64} is not available$",
       "historical state 197e625e06733f288535c0b41d266082c18395761788fe812c9de4e61e001159 "
       "is not available", "robinhood-officiel", -32000, 200, _LE_2026_09_24),
    _s("etat_elague", r"^missing trie node [0-9a-fA-F]{64}\b",
       "missing trie node ecd6a2a548dcb680acd1e23d875fe83c5dd804b0fb233c3a6080f848d0db926c "
       "(path ) state 0xecd6a2a548dcb680acd1e23d875fe83c5dd804b0fb233c3a6080f848d0db926c "
       "is not available, not found", "robinhood-officiel", -32000, 200, _LE_2026_09_24),

    # ---- limitation de débit ------------------------------------------------------------------
    # Mesurée par l'atelier 0 : statut HTTP 429 ET un corps qui a la forme d'une erreur JSON-RPC de
    # code 429. Les deux chemins sont traités dans `rpc.py` ; le remède est d'ATTENDRE.
    _s("debit", r"^too many requests$", "too many requests", "robinhood-officiel", 429, 429,
       _ATELIER_0),

    # ---- refus du frontal HTTP (pas une erreur JSON-RPC) --------------------------------------
    # Cloudflare, code 1010 : les TROIS fournisseurs refusent `Python-urllib/*`, c'est-à-dire
    # l'en-tête que `urllib` pose tout seul quand on n'en met pas. Corps sans JSON.
    _s("entete_refuse", r"^error code: 1010$", "error code: 1010",
       "robinhood-officiel, publicnode, drpc (les trois)", None, 403, _LE_2026_09_24),
)


def classer(reponse):
    """Rend ``(classe, signature)`` pour une réponse de `rpc.py`, ou ``("inconnue", None)``.

    La décision se prend sur le MESSAGE applicatif : `message` d'une erreur JSON-RPC, ou le corps
    d'un refus HTTP. Aucune classe n'est déduite du seul code numérique — deux fournisseurs
    réutilisent `-32000` et `-32701` pour des choses qui n'ont rien à voir.
    """
    txt = None
    if reponse.get("kind") == "rpc_error":
        txt = reponse.get("message")
    elif reponse.get("kind") == "http":
        txt = reponse.get("body")
    if not txt:
        return "inconnue", None
    txt = str(txt).strip()
    trouves = [s for s in SIGNATURES if s["motif"].search(txt)]
    if not trouves:
        return "inconnue", None
    classes = {s["classe"] for s in trouves}
    if len(classes) > 1:
        raise SignatureAmbigue(
            f"ARRÊT : le message {txt[:160]!r} est reconnu par des signatures de classes "
            f"DIFFÉRENTES {sorted(classes)}. La table de `fournisseurs.py` est fautive : ce n'est "
            f"pas à l'ordre de lecture d'arbitrer (KE#138).")
    return trouves[0]["classe"], trouves[0]


def explique(reponse):
    """Phrase d'ARRÊT pour une réponse qu'on ne sait pas exploiter. NOMME toujours le remède."""
    classe, sig = classer(reponse)
    if classe == "inconnue":
        return ("SIGNATURE INCONNUE — ce refus n'est reconnu par aucune signature MESURÉE. On ne "
                "devine pas : deviner « erreur de plage » ferait redécouper à l'infini sur un refus "
                "qui n'en est pas une. Remède : mesurer ce fournisseur et DÉCLARER la signature dans "
                "`veilleur/fournisseurs.py` (SIGNATURES), avec son exemple et sa provenance.")
    return (f"refus de classe « {classe} » (signature mesurée sur {sig['fournisseur']}, "
            f"{sig['mesuré']})")


# ---------------------------------------------------------------------------- profils déclarés

# Ce qui est SPÉCIFIQUE à un fournisseur ne vit pas dans le code : il vit ici, nommé, daté, avec sa
# mesure. `SPINDEX_RPC_PROFIL` choisit un profil ; `SPINDEX_RPC_MAX_LOG_SPAN` le surcharge. Un nom
# de profil inconnu est un ARRÊT (KE#73 : jamais de repli mou sur un défaut).
PROFILS = {
    "robinhood-officiel": {
        "url": "https://rpc.testnet.chain.robinhood.com",
        "client": "nitro/v3.12.0-rc.3",
        "span_logs_max": 1000,
        "pourquoi_span": "aucune limite de PLAGE mesurée (5 000 000 de blocs passent avec un filtre "
                         "d'adresse) mais une limite de 10 000 JOURNAUX : 1 000 blocs est la valeur "
                         "sous laquelle l'atelier 0 n'a jamais vu de refus sur un contrat actif.",
        "archive": False,
        "profondeur_etat_blocs": "entre 5 000 et 7 000 (mesuré 2026-09-24) — fenêtre ≈ 19 min",
        "filtre_adresse_exige": False,
        "en_tetes": "Cloudflare : `Python-urllib/*` refusé en 403 « error code: 1010 ».",
    },
    "publicnode": {
        "url": "https://robinhood-sepolia-rpc.publicnode.com",
        "client": "nitro/v3599aca-modified",
        "span_logs_max": 50_000,
        "pourquoi_span": "limite annoncée ET mesurée : 50 000 blocs acceptés, 100 000 refusés.",
        "archive": False,
        "profondeur_etat_blocs": "moins de 5 000 (mesuré 2026-09-24) — fenêtre ≈ 19 s, "
                                 "REFUSÉ par la garde `fenêtre_sous_besoin` (besoin 480 s)",
        "filtre_adresse_exige": True,
        "en_tetes": "Cloudflare : `Python-urllib/*` refusé en 403 « error code: 1010 ».",
    },
    "drpc": {
        "url": "https://robinhood-testnet.drpc.org",
        "client": "Geth/v10.0.0/drpc (identité du mandataire, pas du nœud amont)",
        "span_logs_max": 101,
        "pourquoi_span": "MESURÉ par dichotomie, trois fois : 101 blocs acceptés, 102 refusés. "
                         "Le message du fournisseur annonce 10 000 — il ment, et on ne le croit pas.",
        "archive": False,
        "profondeur_etat_blocs": "2026-09-24 : servi jusqu'à 100 000 000 de blocs (archive). "
                                 "2026-09-28 : l'état par NUMÉRO de bloc n'est servi à AUCUNE profondeur, "
                                 "tête comprise (`etat_indisponible`, 8/8 refus capturés, 0 sur 78 essais "
                                 "entre 0 et 30 blocs) — INAPTE aux sections qui lisent l'état à un bloc "
                                 "épinglé et à la sonde de fenêtre",
        "filtre_adresse_exige": False,
        "en_tetes": "Cloudflare : `Python-urllib/*` refusé en 403 « error code: 1010 ». "
                    "Les erreurs applicatives arrivent en HTTP 400, pas 200.",
        # CHOIX d'exploitation (pas une mesure) : dRPC a rendu un 408 « Request timeout » après 2,1 s
        # sur une plage de 101 blocs (run 36469251579). 5 relances à 2, 4, 8, 16, 30 s = 60 s au plus
        # par appel, puis échec nommé. Un profil SANS cette clé ne relance pas : le refus transitoire
        # y est un ARRÊT qui nomme la clé à déclarer (KE#105 — pas de défaut qui masquerait un oubli).
        "relance_transitoire": {"essais": 5, "attente_initiale_s": 2.0, "attente_max_s": 30.0},
    },
}

# Défaut du paquet : la valeur la plus PRUDENTE des profils mesurés qui ne soit pas spécifique à un
# fournisseur unique. 1 000 blocs passe partout SAUF sur dRPC, qui se signale et fait redécouper.
SPAN_LOGS_DEFAUT = 1000
# Plancher de découpage : sous cette taille, on n'essaie plus, on échoue bruyamment.
SPAN_LOGS_PLANCHER = 16

# En-tête mesuré comme ACCEPTÉ par les trois fournisseurs.
USER_AGENT_DEFAUT = "spindex-veilleur/1 (read-only)"
# En-tête mesuré comme REFUSÉ (403, Cloudflare 1010) par les trois. C'est celui que `urllib` pose
# tout seul : un appelant qui passe `user_agent=None` se ferait refuser sans comprendre pourquoi.
MOTIF_USER_AGENT_REFUSE = re.compile(r"^Python-urllib/", re.IGNORECASE)

# Profondeur maximale sondée par la dichotomie de fenêtre d'état. 200 000 blocs à 0,156 s/bloc
# (cadence MESURÉE le 2026-09-24) = 8 h 40, soit 65 × le besoin de 480 s : un nœud qui sert encore
# l'état à cette profondeur couvre le besoin, et on n'a pas besoin de savoir de combien.
PROFONDEUR_MAX_DEFAUT = 200_000
# Avance à laquelle on interroge un bloc qui NE PEUT PAS exister, pour prouver que la sonde sait
# dire NON (KE#121). 1 000 000 de blocs = 43 h à la cadence mesurée. Les trois fournisseurs y
# refusent, chacun avec sa formulation (`bloc_inconnu`).
TEMOIN_AVANCE_BLOCS = 1_000_000
