"""Les contrôles bloquants. C'est ici que vit la garantie de §21, et nulle part ailleurs.

Trois états, et ils ne se confondent JAMAIS (KE#105)
---------------------------------------------------
  OK            — j'ai vérifié, c'est vrai.
  ECHEC         — j'ai vérifié, c'est FAUX.
  INDISPONIBLE  — je n'ai PAS pu vérifier.

« Rien à signaler » et « je n'ai pas pu vérifier » doivent être impossibles à confondre : c'est la
raison d'être du troisième état. Un contrôle INDISPONIBLE n'est jamais compté comme OK, et il
n'autorise jamais un feu vert. Un `ECHEC` l'emporte sur un `INDISPONIBLE` dans le verdict global : si
une seule preuve de fausseté existe, la table est mauvaise, point.

Ce que la revue adverse a démontré, et qu'il ne faut jamais réaffaiblir
----------------------------------------------------------------------
`test_revue5_keeperDrainsThePrize_withOneLeafTree` : une table de poids à UNE SEULE FEUILLE au nom du
keeper satisfait **la racine** et **le pavage exact** — les deux contrôles que la première rédaction
de §21 demandait. Elle vole 100 % de la dotation. Seuls **OD-F (exhaustivité)** et **OD-G (égalité
des poids)** portent la garantie. Ils sont marqués `PORTE_LA_GARANTIE = True` et le banc exige qu'ils
soient les motifs du refus sur cette table exacte — pas « la table est refusée », mais « la table est
refusée POUR CETTE RAISON ».

L'ensemble de référence vient de la CHAÎNE, jamais du sujet (KE#130 / KE#127)
-----------------------------------------------------------------------------
OD-F et OD-G portent la garantie, mais leur ensemble de référence — la reconstruction — est bâti par
le veilleur LUI-MÊME à partir du flux de journaux qu'il a lu ou figé. Une adresse absente à la fois
de la reconstruction ET de la table n'était comptée nulle part : ni OD-F ni OD-G ne peuvent la voir,
parce qu'aucun des deux n'a de borne qui vienne d'ailleurs. Deux entrées mènent là — un nœud RPC qui
omet un `Staked` au moment du figeage, et un cache local empoisonné — et l'une comme l'autre produit
un GO sur une table qui amute un staker réel.

**OD-J** ferme la classe avec la seule borne qui ne vienne pas du sujet : `totalStaked()` relu
on-chain au bloc d'instantané, en **ÉGALITÉ EXACTE**. Une inégalité serait satisfaite par la panne du
côté sous test (KE#121) ; une somme tirée de la table ou de la reconstruction seule serait le sujet
confronté à lui-même. Ses deux jambes sont indépendantes par construction :
  (1) la somme des `stakeOf` RELUS un par un au bloc d'instantané sur toutes les cibles connues ;
  (2) la somme des montants REJOUÉS depuis les journaux.
La jambe (1) survit à un cache empoisonné (elle ne lit aucun cache) ; la jambe (2) survit à une
lecture directe qui mentirait sur une adresse (elle ne lit aucun état). Les deux sont comparées au
MÊME agrégat on-chain, que personne ne peut énumérer ni reconstruire. `totalStaked` est bien
`Σ stakeOf` par construction du contrat (`totalStaked += amount` / `-= amount`, SpindexRewards.sol).

Assertion de CARDINAL partout (KE#111 / KE#121)
-----------------------------------------------
Chaque contrôle qui itère porte le nombre de comparaisons réellement faites, et la suite refuse de se
conclure si un contrôle a comparé ZÉRO élément. Ce projet a trouvé quatre vagues de contrôles qui
passaient à vide, chacune cachée dans le correctif de la précédente : c'est son piège par défaut.
"""
from .merkle import leaf_draw, leaf_week, root as merkle_root

OK = "OK"
ECHEC = "ECHEC"
INDISPONIBLE = "INDISPONIBLE"


class Control:
    def __init__(self, cid, titre, statut, motif="", observé=None, attendu=None,
                 comparaisons=None, porte_la_garantie=False):
        self.id = cid
        self.titre = titre
        self.statut = statut
        self.motif = motif
        self.observé = observé
        self.attendu = attendu
        self.comparaisons = comparaisons
        self.porte_la_garantie = porte_la_garantie

    def to_dict(self):
        d = {"id": self.id, "titre": self.titre, "statut": self.statut,
             "porte_la_garantie": self.porte_la_garantie}
        if self.motif:
            d["motif"] = self.motif
        if self.observé is not None:
            d["observé"] = self.observé
        if self.attendu is not None:
            d["attendu"] = self.attendu
        if self.comparaisons is not None:
            d["comparaisons"] = self.comparaisons
        return d

    def __repr__(self):
        return f"<{self.id} {self.statut} {self.motif[:60]}>"


class SuiteError(RuntimeError):
    pass


class Suite:
    """Une suite de contrôles, avec son cardinal DÉCLARÉ. Un contrôle manquant est un ARRÊT, pas un
    contrôle réussi : c'est la différence entre « les 6 contrôles sont verts » et « j'ai lancé 4
    contrôles et aucun n'a rouspété »."""

    def __init__(self, nom, ids_déclarés):
        self.nom = nom
        self.ids_déclarés = tuple(ids_déclarés)
        self.controls = []

    def add(self, c):
        self.controls.append(c)
        return c

    def seal(self):
        got = tuple(c.id for c in self.controls)
        if got != self.ids_déclarés:
            raise SuiteError(
                f"ARRÊT : la suite « {self.nom} » a produit {got} pour {self.ids_déclarés} déclarés. "
                f"Un contrôle qui ne s'exécute pas ne doit JAMAIS ressembler à un contrôle qui passe.")
        for c in self.controls:
            if c.statut == OK and c.comparaisons is not None and c.comparaisons == 0:
                raise SuiteError(
                    f"ARRÊT : le contrôle {c.id} est vert avec ZÉRO comparaison. Un contrôle qui itère "
                    f"à vide n'est pas un contrôle (KE#111).")
        return self

    @property
    def verdict(self):
        if any(c.statut == ECHEC for c in self.controls):
            return "REFUS"
        if any(c.statut == INDISPONIBLE for c in self.controls):
            return "INDISPONIBLE"
        if not self.controls:
            raise SuiteError("ARRÊT : suite vide — pas de feu vert sur zéro contrôle.")
        return "GO"

    @property
    def motifs(self):
        return [c.id for c in self.controls if c.statut in (ECHEC, INDISPONIBLE)]

    def to_dict(self):
        return {"suite": self.nom, "verdict": self.verdict,
                "contrôles": [c.to_dict() for c in self.controls],
                "motifs": self.motifs}


# ====================================================================== outils communs

def _dup_control(cid, table):
    """Feuilles strictement identiques, et joueurs en double."""
    n = len(table.leaves)
    seen = {}
    dup_leaf = []
    for i, lf in enumerate(table.leaves):
        key = tuple(sorted((k, str(v)) for k, v in lf.items()))
        if key in seen:
            dup_leaf.append((seen[key], i, lf["player"]))
        seen[key] = i
    players = [lf["player"] for lf in table.leaves]
    counts = {}
    for p in players:
        counts[p] = counts.get(p, 0) + 1
    dup_player = sorted(p for p, c in counts.items() if c > 1)
    if dup_leaf or dup_player:
        return Control(cid, "aucune feuille ni joueur en double", ECHEC,
                       motif=f"{len(dup_leaf)} feuille(s) identiques, {len(dup_player)} joueur(s) répétés "
                             f"{dup_player[:5]}. Un joueur ne peut être payé qu'une fois : une seconde "
                             f"feuille est de l'argent immobilisé au mieux, une préparation au pire.",
                       observé={"feuilles_dupliquées": len(dup_leaf), "joueurs_dupliqués": dup_player[:20]},
                       comparaisons=n)
    return Control(cid, "aucune feuille ni joueur en double", OK,
                   observé={"feuilles": n, "joueurs_distincts": len(counts)}, comparaisons=n)


def _root_control(cid, table, leaf_fn):
    leaves = [leaf_fn(lf) for lf in table.leaves]
    if len(leaves) != len(table.leaves):
        raise SuiteError("ARRÊT : cardinal des feuilles hachées incohérent (KE#111).")
    got = merkle_root(leaves)
    if got != table.root:
        return Control(cid, "racine recalculée depuis la table == racine annoncée", ECHEC,
                       motif="la racine recalculée ne correspond pas à celle que le Safe s'apprête à signer.",
                       observé="0x" + got.hex(), attendu="0x" + table.root.hex(),
                       comparaisons=len(leaves))
    return Control(cid, "racine recalculée depuis la table == racine annoncée", OK,
                   observé="0x" + got.hex(), comparaisons=len(leaves))


# ====================================================================== avant `postWeek`

POSTWEEK_IDS = ("PW-A", "PW-B", "PW-C", "PW-D", "PW-E", "PW-F")

ZERO32 = "0x" + "00" * 32


class WeekEvidence:
    """Pièces pour les contrôles de semaine.

    CONTRAINTE STRUCTURELLE, trouvée à l'écriture et à retenir : **aucune lecture d'ÉTAT n'est
    possible à un bloc finalisé sur le RPC public.** La fenêtre d'état mesurée vaut ~6 231 blocs
    (10 min 28 s) tandis que `finalized` est à −12 031 blocs (20 min 13 s) : `getWeek` au bloc
    `finalized` est REFUSÉ par le nœud. La règle « les contrôles bloquants ne se prononcent que sur
    `finalized` » n'est donc pas applicable telle quelle à l'état.

    Ce qui la remplace, et qui est meilleur : les JOURNAUX remontent à la genèse, pour toujours.
    L'enveloppe versée et la racine déjà publiée sont donc reconstituées depuis `WeekFunded` /
    `WeekPosted` **au bloc finalisé** (réorg-sûr), et confrontées à la lecture d'état **à la tête**
    (fraîche, mais réorganisable). Les deux doivent s'accorder ; la borne retenue est la PLUS
    PRUDENTE des deux.
    """

    def __init__(self):
        self.week_tête = None           # getWeek à la tête
        self.funded_journaux = None     # Σ WeekFunded jusqu'à `finalized`
        self.funded_évènement = None    # dernier champ `funded` cumulé porté par WeekFunded
        self.racine_journaux = None     # racine de WeekPosted jusqu'à `finalized`, ou None
        self.n_versements = 0
        self.erreurs = {}


def run_postweek(table, ev: WeekEvidence):
    """Les quatre contrôles de §21 pour une semaine, plus les doublons et la non-réécriture."""
    s = Suite("postWeek", POSTWEEK_IDS)

    s.add(_root_control("PW-A", table,
                        lambda lf: leaf_week(lf["player"], lf["weekId"],
                                             lf["rakebackUsdg"], lf["revshareUsdg"])))

    somme = sum(lf["rakebackUsdg"] + lf["revshareUsdg"] for lf in table.leaves)
    s.add(Control("PW-B", "Σ feuilles == totalUsdg",
                  OK if somme == table.total else ECHEC,
                  motif="" if somme == table.total else
                        "la somme des feuilles ne vaut pas le totalUsdg annoncé : une semaine sous-financée "
                        "devient une course au premier arrivé.",
                  observé=str(somme), attendu=str(table.total), comparaisons=len(table.leaves)))

    s.add(_funded_control(table, ev))

    s.add(Control("PW-D", "leafCount == nombre de feuilles",
                  OK if table.leaf_count == len(table.leaves) else ECHEC,
                  observé=table.leaf_count, attendu=len(table.leaves), comparaisons=len(table.leaves)))

    s.add(_dup_control("PW-E", table))

    s.add(_already_posted_control(table, ev))
    return s.seal()


def _funded_control(table, ev: WeekEvidence):
    if ev.funded_journaux is None:
        return Control("PW-C", "totalUsdg ≤ funded(weekId)", INDISPONIBLE,
                       motif=ev.erreurs.get("journaux") or "journaux `WeekFunded` indisponibles")
    funded_tête = ev.week_tête["funded"] if ev.week_tête else None
    # incohérence entre les deux témoins : on ne choisit pas, on refuse.
    if (ev.funded_évènement is not None and ev.funded_journaux != ev.funded_évènement):
        return Control("PW-C", "totalUsdg ≤ funded(weekId)", ECHEC,
                       motif=f"la somme des `WeekFunded` ({ev.funded_journaux}) diffère du cumul que "
                             f"le dernier événement annonce ({ev.funded_évènement}) : un journal manque.",
                       observé={"somme_journaux": str(ev.funded_journaux),
                                "cumul_événement": str(ev.funded_évènement)},
                       comparaisons=max(1, ev.n_versements))
    if ev.n_versements == 0:
        return Control("PW-C", "totalUsdg ≤ funded(weekId)", ECHEC,
                       motif="la semaine n'a JAMAIS été versée (aucun `WeekFunded` jusqu'au bloc "
                             "finalisé) : `postWeek` révoquerait, et une table publiée sur une "
                             "enveloppe inexistante n'engage rien.",
                       observé={"versements": 0, "funded_à_la_tête": None if funded_tête is None
                                else str(funded_tête)},
                       attendu="au moins un WeekFunded", comparaisons=1)
    bornes = [ev.funded_journaux] + ([funded_tête] if funded_tête is not None else [])
    borne = min(bornes)
    ok = table.total <= borne
    return Control("PW-C", "totalUsdg ≤ funded(weekId)", OK if ok else ECHEC,
                   motif="" if ok else "la table promet plus que l'enveloppe versée.",
                   observé={"totalUsdg": str(table.total),
                            "funded_journaux_finalisés": str(ev.funded_journaux),
                            "funded_à_la_tête": None if funded_tête is None else str(funded_tête),
                            "borne_retenue": str(borne), "versements": ev.n_versements},
                   attendu="totalUsdg ≤ min(journaux finalisés, tête)",
                   comparaisons=len(bornes))


def _already_posted_control(table, ev: WeekEvidence):
    racine_tête = ev.week_tête["root"] if ev.week_tête else None
    vues = [r for r in (ev.racine_journaux, racine_tête) if r is not None and r != ZERO32]
    if ev.racine_journaux is None and racine_tête is None:
        return Control("PW-F", "la semaine n'est pas déjà publiée", INDISPONIBLE,
                       motif="ni les journaux ni la vue `getWeek` n'ont pu être lus.")
    if not vues:
        return Control("PW-F", "la semaine n'est pas déjà publiée", OK,
                       observé={"journaux": ev.racine_journaux, "tête": racine_tête}, comparaisons=2)
    ma = "0x" + table.root.hex()
    même = all(v.lower() == ma for v in vues)
    return Control("PW-F", "la semaine n'est pas déjà publiée", ECHEC,
                   motif=("une racine IDENTIQUE est déjà publiée : `postWeek` révoquerait "
                          "(`WeekAlreadyPosted`)." if même else
                          "une racine DIFFÉRENTE est déjà publiée pour cette semaine. `postWeek` n'est "
                          "pas rejouable : deux racines pour un même weekId signifient que deux "
                          "transactions ont été soumises. P0, décision humaine exigée."),
                   observé={"journaux": ev.racine_journaux, "tête": racine_tête, "table": ma},
                   attendu=ZERO32, comparaisons=len(vues))


# ====================================================================== avant `openDraw`

OPENDRAW_IDS = ("OD-A", "OD-B", "OD-C", "OD-D", "OD-E", "OD-F", "OD-G", "OD-H", "OD-I", "OD-J")


class DrawEvidence:
    """Les pièces que les contrôles OD-F / OD-G consomment. Chaque pièce absente porte SA raison :
    un contrôle qui ne sait pas pourquoi il est indisponible n'aide personne."""

    def __init__(self):
        self.stakers_reconstruits = None      # set(adresse) avec amount > 0 au bloc d'instantané
        self.poids_reconstruits = None        # {adresse: effectiveStakeOf calculé au bloc d'instantané}
        self.stake_direct = None              # {adresse: stakeOf lu AU BLOC d'instantané}
        self.effectif_direct = None           # {adresse: effectiveStakeOf lu AU BLOC d'instantané}
        self.effectif_vivant = None           # {adresse: effectiveStakeOf lu à la TÊTE}
        self.poids_à_la_tête = None           # {adresse: reconstruction recalculée à la TÊTE}
        self.erreurs = {}                     # {"reconstruction": "...", "direct": "...", ...}
        self.recoupement_halving = None
        self.fenêtre = None
        # --- OD-J : la seule borne qui ne vienne PAS du sujet (KE#130). `total_staked_onchain` est
        # lu par un `eth_call` au bloc d'instantané ; les deux sommes lui sont confrontées en
        # ÉGALITÉ EXACTE. `cibles` est l'union {stakers reconstruits} ∪ {joueurs de la table} : c'est
        # l'ensemble sur lequel la jambe directe a réellement lu.
        self.total_staked_onchain = None      # totalStaked() @ bloc d'instantané
        self.total_staked_reconstruit = None  # somme des montants rejoués depuis les journaux
        self.cibles = None                    # l'union effectivement lue (cardinal de la jambe 1)


def run_opendraw(reader, table, ev: DrawEvidence, block="latest"):
    s = Suite("openDraw", OPENDRAW_IDS)

    # ---- OD-A : racine des poids
    s.add(_root_control("OD-A", table,
                        lambda lf: leaf_draw(lf["player"], lf["weekId"], lf["index"],
                                             lf["cumulativeFrom"], lf["cumulativeTo"])))

    # ---- OD-B : pavage EXACT de [0, totalWeight), sans trou ni recouvrement
    s.add(_tiling_control(table))

    # ---- OD-C : totalWeight conforme
    somme = sum(lf["cumulativeTo"] - lf["cumulativeFrom"] for lf in table.leaves
                if lf["cumulativeTo"] >= lf["cumulativeFrom"])
    okc = somme == table.total
    s.add(Control("OD-C", "totalWeight == somme des largeurs d'intervalle",
                  OK if okc else ECHEC,
                  motif="" if okc else "un totalWeight gonflé renvoie la part non couverte au Safe, "
                                       "sans qu'aucune transaction ne paraisse anormale.",
                  observé=str(somme), attendu=str(table.total), comparaisons=len(table.leaves)))

    # ---- OD-D : la dotation est RÉELLEMENT détenue et libre
    s.add(_prize_control(reader, table, block))

    # ---- OD-E : doublons
    s.add(_dup_control("OD-E", table))

    # ---- OD-F / OD-G : les deux contrôles qui ferment P0-1
    f, g = _exhaustivity_and_weights(table, ev)
    s.add(f)
    s.add(g)

    # ---- OD-H : le tirage n'est pas déjà ouvert
    try:
        d = reader.draw(table.week_id, block)
        wr = d.get("weightsRoot")
        zero = "0x" + "00" * 32
        if wr == zero:
            s.add(Control("OD-H", "le tirage n'est pas déjà ouvert", OK, observé=wr, comparaisons=1))
        else:
            same = wr.lower() == ("0x" + table.root.hex())
            s.add(Control("OD-H", "le tirage n'est pas déjà ouvert", ECHEC,
                          motif=("le tirage est déjà ouvert avec la MÊME racine : `openDraw` révoquerait."
                                 if same else
                                 "le tirage est déjà ouvert avec une racine DIFFÉRENTE. `openDraw` n'est "
                                 "pas rejouable : P0, décision humaine exigée."),
                          observé=wr, attendu=zero, comparaisons=1))
    except Exception as e:  # noqa: BLE001
        s.add(Control("OD-H", "le tirage n'est pas déjà ouvert", INDISPONIBLE,
                      motif=f"la vue `getDraw` n'a pas pu être lue : {e}"))

    # ---- OD-I : la reconstruction est PROUVÉE à la tête (c'est ce qui la rend digne de confiance)
    s.add(_recon_proof_control(ev))

    # ---- OD-J : la borne vient de la CHAÎNE (KE#130). Sans lui, OD-F et OD-G se contentent d'un
    # ensemble de référence que le sujet a lui-même produit.
    s.add(_total_staked_control(ev))

    return s.seal()


def _tiling_control(table):
    n = len(table.leaves)
    rows = sorted(((lf["cumulativeFrom"], lf["cumulativeTo"], lf["index"], lf["player"])
                   for lf in table.leaves), key=lambda r: (r[0], r[1]))
    problems = []
    for a, b, idx, p in rows:
        if b <= a:
            problems.append(f"intervalle vide ou inversé [{a}, {b}) pour {p}")
    prev_end = 0
    for a, b, idx, p in rows:
        if a != prev_end:
            problems.append(
                f"{'trou' if a > prev_end else 'recouvrement'} entre {prev_end} et {a} (joueur {p})")
        prev_end = max(prev_end, b)
    if prev_end != table.total:
        problems.append(f"la borne haute du pavage vaut {prev_end} et non totalWeight = {table.total}")
    # index : la convention exige des index 0..n-1 distincts, sinon deux feuilles se disputent une place
    idxs = sorted(lf["index"] for lf in table.leaves)
    if idxs != list(range(n)):
        problems.append(f"les index ne pavent pas 0..{n - 1}")
    if problems:
        return Control("OD-B", "les intervalles pavent exactement [0, totalWeight)", ECHEC,
                       motif="; ".join(problems[:6]) + ("…" if len(problems) > 6 else ""),
                       observé={"problèmes": len(problems), "borne_haute": str(prev_end)},
                       attendu=f"pavage exact de [0, {table.total})", comparaisons=n)
    return Control("OD-B", "les intervalles pavent exactement [0, totalWeight)", OK,
                   observé={"intervalles": n, "borne_haute": str(prev_end)}, comparaisons=n)


def _prize_control(reader, table, block):
    if table.prize_token is None or table.prize_amount is None:
        return Control("OD-D", "la dotation est détenue et libre", INDISPONIBLE,
                       motif="la table ne déclare pas `prizeToken` / `prizeAmount` : le veilleur ne peut "
                             "pas vérifier ce que le Safe s'apprête à engager.")
    try:
        free = reader.free_balance(table.prize_token, block)
    except Exception as e:  # noqa: BLE001
        return Control("OD-D", "la dotation est détenue et libre", INDISPONIBLE,
                       motif=f"`freeBalance({table.prize_token})` n'a pas pu être lu : {e}")
    ok = free >= table.prize_amount
    return Control("OD-D", "la dotation est détenue et libre", OK if ok else ECHEC,
                   motif="" if ok else "le contrat ne détient pas librement la dotation annoncée : "
                                       "`openDraw` révoquerait (`InsufficientFreeBalance`).",
                   observé={"freeBalance": str(free), "prizeAmount": str(table.prize_amount),
                            "prizeToken": table.prize_token},
                   attendu="freeBalance ≥ prizeAmount", comparaisons=1)


def _exhaustivity_and_weights(table, ev: DrawEvidence):
    """OD-F et OD-G — LES deux contrôles qui portent la garantie. Ne jamais les affaiblir.

    OD-F : l'ensemble des feuilles est EXACTEMENT l'ensemble des adresses de `stakeOf > 0` au bloc
           d'instantané. L'ensemble ne peut venir que des JOURNAUX (aucune énumération on-chain
           n'existe), et il est CONFIRMÉ par une lecture directe au bloc d'instantané : chaque feuille
           hors reconstruction doit avoir `stakeOf == 0` là-bas, et chaque staker reconstruit doit
           avoir `stakeOf > 0`.
    OD-G : le poids de chaque feuille égale son `effectiveStakeOf` RELU au bloc d'instantané, et la
           reconstruction et la lecture directe doivent en plus s'accorder entre elles.
    """
    feuilles = {lf["player"]: lf["cumulativeTo"] - lf["cumulativeFrom"] for lf in table.leaves}

    if ev.stakers_reconstruits is None:
        motif = ev.erreurs.get("reconstruction") or "reconstruction absente"
        return (Control("OD-F", "exhaustivité : feuilles == stakers au bloc d'instantané", INDISPONIBLE,
                        motif=motif, porte_la_garantie=True),
                Control("OD-G", "chaque poids == effectiveStakeOf au bloc d'instantané", INDISPONIBLE,
                        motif=motif, porte_la_garantie=True))

    if ev.stake_direct is None or ev.effectif_direct is None:
        motif = ev.erreurs.get("direct") or (
            "lecture directe au bloc d'instantané impossible. La fenêtre d'état du RPC public ne dure "
            "que quelques minutes : au-delà, le contrôle normatif de §21 n'est PAS exécutable, et le "
            "veilleur le dit au lieu de rendre un feu vert dégradé.")
        return (Control("OD-F", "exhaustivité : feuilles == stakers au bloc d'instantané", INDISPONIBLE,
                        motif=motif, porte_la_garantie=True),
                Control("OD-G", "chaque poids == effectiveStakeOf au bloc d'instantané", INDISPONIBLE,
                        motif=motif, porte_la_garantie=True))

    # ------------------------------------------------------------------ OD-F
    stakers = set(ev.stakers_reconstruits)
    if not stakers:
        f = Control("OD-F", "exhaustivité : feuilles == stakers au bloc d'instantané", ECHEC,
                    motif="AUCUN staker reconstruit au bloc d'instantané. Un ensemble vide rendrait "
                          "l'égalité d'ensembles VACUEMENT vraie pour une table à une feuille : c'est "
                          "précisément le trou que P0-1 exploite (KE#111).",
                    observé={"stakers": 0}, comparaisons=0, porte_la_garantie=True)
    else:
        manquants = sorted(stakers - set(feuilles))
        en_trop = sorted(set(feuilles) - stakers)
        # la lecture DIRECTE au bloc d'instantané confirme les deux directions
        faux_positifs = sorted(a for a in en_trop if ev.stake_direct.get(a, 0) > 0)
        confirmés_nuls = sorted(a for a in en_trop if ev.stake_direct.get(a, 0) == 0)
        recon_contredite = sorted(a for a in stakers if ev.stake_direct.get(a, -1) == 0)
        n_cmp = len(stakers | set(feuilles))
        if manquants or en_trop or recon_contredite:
            détail = []
            if manquants:
                détail.append(f"{len(manquants)} staker(s) ABSENTS de la table (ex. {manquants[:3]})")
            if confirmés_nuls:
                détail.append(f"{len(confirmés_nuls)} feuille(s) dont `stakeOf` vaut 0 au bloc "
                              f"d'instantané (ex. {confirmés_nuls[:3]}) : ces adresses ne sont PAS "
                              f"des stakers")
            if faux_positifs:
                détail.append(f"{len(faux_positifs)} feuille(s) absentes de la reconstruction mais dont "
                              f"`stakeOf` > 0 : la reconstruction est en défaut, alerte")
            if recon_contredite:
                détail.append(f"{len(recon_contredite)} staker(s) reconstruit(s) dont la lecture directe "
                              f"dit `stakeOf == 0` : reconstruction et chaîne divergent")
            f = Control("OD-F", "exhaustivité : feuilles == stakers au bloc d'instantané", ECHEC,
                        motif=" ; ".join(détail),
                        observé={"feuilles": len(feuilles), "stakers": len(stakers),
                                 "manquants": len(manquants), "en_trop": len(en_trop),
                                 "exemples_manquants": manquants[:5], "exemples_en_trop": en_trop[:5]},
                        attendu="{feuilles} == {stakeOf > 0 au bloc d'instantané}",
                        comparaisons=n_cmp, porte_la_garantie=True)
        else:
            f = Control("OD-F", "exhaustivité : feuilles == stakers au bloc d'instantané", OK,
                        observé={"feuilles": len(feuilles), "stakers": len(stakers)},
                        comparaisons=n_cmp, porte_la_garantie=True)

    # ------------------------------------------------------------------ OD-G
    écarts = []
    désaccords_internes = []
    n = 0
    for a, poids in feuilles.items():
        n += 1
        direct = ev.effectif_direct.get(a)
        if direct is None:
            écarts.append((a, str(poids), "non lu au bloc d'instantané"))
            continue
        recon = ev.poids_reconstruits.get(a, 0) if ev.poids_reconstruits else None
        if recon is not None and recon != direct:
            désaccords_internes.append((a, str(recon), str(direct)))
        if poids != direct:
            écarts.append((a, str(poids), str(direct)))
    # les stakers absents de la table sont traités par OD-F ; ici on vérifie AUSSI que la
    # reconstruction et la chaîne s'accordent sur EUX, sinon la preuve principale n'est pas prouvée.
    for a in sorted(stakers - set(feuilles)):
        n += 1
        direct = ev.effectif_direct.get(a)
        recon = ev.poids_reconstruits.get(a) if ev.poids_reconstruits else None
        if direct is not None and recon is not None and direct != recon:
            désaccords_internes.append((a, str(recon), str(direct)))

    if n == 0:
        g = Control("OD-G", "chaque poids == effectiveStakeOf au bloc d'instantané", ECHEC,
                    motif="aucune comparaison de poids n'a eu lieu (KE#111).",
                    comparaisons=0, porte_la_garantie=True)
    elif écarts or désaccords_internes:
        motif = []
        if écarts:
            motif.append(f"{len(écarts)} poids divergent de `effectiveStakeOf` relu au bloc "
                         f"d'instantané (ex. {écarts[:3]})")
        if désaccords_internes:
            motif.append(f"{len(désaccords_internes)} désaccord(s) entre la reconstruction par les "
                         f"journaux et la lecture directe (ex. {désaccords_internes[:3]}) : la preuve "
                         f"principale est elle-même en défaut, c'est une alerte en soi")
        g = Control("OD-G", "chaque poids == effectiveStakeOf au bloc d'instantané", ECHEC,
                    motif=" ; ".join(motif),
                    observé={"écarts": len(écarts), "désaccords_reconstruction_vs_chaîne":
                             len(désaccords_internes)},
                    attendu="poids(a) == effectiveStakeOf(a) au bloc d'instantané",
                    comparaisons=n, porte_la_garantie=True)
    else:
        g = Control("OD-G", "chaque poids == effectiveStakeOf au bloc d'instantané", OK,
                    observé={"poids_comparés": len(feuilles), "stakers_recoupés": n},
                    comparaisons=n, porte_la_garantie=True)
    return f, g


def _recon_proof_control(ev: DrawEvidence):
    """La reconstruction n'a de valeur que si elle est PROUVÉE. On la compare aux lectures VIVANTES
    d'`effectiveStakeOf` à la tête : une reconstruction dont l'exactitude est vérifiée à chaque tour
    est un meilleur témoin qu'un nœud archive que personne ne contrôle."""
    if ev.effectif_vivant is None or ev.poids_à_la_tête is None:
        return Control("OD-I", "la reconstruction est prouvée par les lectures vivantes", INDISPONIBLE,
                       motif=ev.erreurs.get("vivant") or "lectures vivantes indisponibles")
    communes = sorted(set(ev.effectif_vivant) & set(ev.poids_à_la_tête))
    if not communes:
        return Control("OD-I", "la reconstruction est prouvée par les lectures vivantes", ECHEC,
                       motif="aucune adresse commune entre la reconstruction et les lectures vivantes : "
                             "la preuve continue n'a comparé RIEN (KE#111).", comparaisons=0)
    diff = [(a, str(ev.poids_à_la_tête[a]), str(ev.effectif_vivant[a]))
            for a in communes if ev.poids_à_la_tête[a] != ev.effectif_vivant[a]]
    # le recoupement des deux chemins de halving (événement vs Claimed) fait partie de la preuve
    rh = ev.recoupement_halving or {}
    if rh.get("divergences"):
        return Control("OD-I", "la reconstruction est prouvée par les lectures vivantes", ECHEC,
                       motif=f"les deux chemins de halving divergent sur {rh['divergences']} adresse(s) "
                             f"(ex. {rh.get('détail', [])[:2]}) : l'un des deux réplique mal le "
                             f"garde-fou du contrat.",
                       observé=rh, comparaisons=rh.get("adresses_comparées", 0))
    if diff:
        return Control("OD-I", "la reconstruction est prouvée par les lectures vivantes", ECHEC,
                       motif=f"{len(diff)} divergence(s) entre la reconstruction et `effectiveStakeOf` "
                             f"lu à la tête (ex. {diff[:3]}).",
                       observé={"divergences": len(diff)}, comparaisons=len(communes))
    return Control("OD-I", "la reconstruction est prouvée par les lectures vivantes", OK,
                   observé={"adresses_recoupées": len(communes),
                            "recoupement_halving": rh.get("adresses_comparées")},
                   comparaisons=len(communes))


OD_J_TITRE = "somme des stakes == totalStaked() relu on-chain au bloc d'instantané"


def _total_staked_control(ev: DrawEvidence):
    """OD-J — LA borne qui ne vient pas du sujet (KE#130 / KE#127), et elle porte la garantie.

    OD-F compare la table à la reconstruction ; OD-G compare les poids à des lectures faites sur
    l'union de ces deux ensembles. Aucun des deux ne peut voir une adresse absente des DEUX : il
    n'existe aucune énumération on-chain des stakers, donc l'ensemble de référence est forcément
    bâti par le veilleur. `totalStaked()` est le seul agrégat que la chaîne tient elle-même sur cet
    ensemble inénumérable — c'est pour cela qu'il ferme la classe, et seulement en ÉGALITÉ EXACTE :
    `somme <= total` serait vrai de toute omission, et `somme >= total` serait satisfait par la panne
    du côté sous test (KE#121).

    Deux jambes, indépendantes par leur SOURCE, confrontées au même agrégat :
      (1) `Σ stakeOf` relus un par un au bloc d'instantané — ne traverse aucun cache local ;
      (2) `Σ amount` rejoués depuis les journaux — ne traverse aucune lecture d'état.
    Un cache empoisonné casse (2) seule ; un nœud qui ment sur `stakeOf` casse (1) seule ; un nœud
    qui omet un `Staked` au figeage casse (2) — et (1) aussi dès que l'adresse n'est pas non plus
    dans la table. Aucune des deux ne peut être déduite de l'autre.
    """
    if ev.total_staked_onchain is None:
        return Control("OD-J", OD_J_TITRE, INDISPONIBLE,
                       motif=ev.erreurs.get("total_staked")
                       or "`totalStaked()` n'a pas pu être relu au bloc d'instantané. Sans cette "
                          "borne, l'exhaustivité ne repose que sur ce que le veilleur a lui-même lu "
                          "(KE#130) : ce n'est pas un feu vert dégradé, c'est un « je n'ai pas pu "
                          "vérifier ».",
                       porte_la_garantie=True)

    jambes = []           # (nom, somme, cardinal)
    if ev.stake_direct is not None and ev.cibles is not None:
        # `cibles == []` compte comme une jambe PRÉSENTE et VIDE, pas comme une jambe absente : la
        # distinction décide entre ECHEC (somme vide, KE#111) et INDISPONIBLE (rien à dire).
        jambes.append(("lecture directe `stakeOf` au bloc d'instantané",
                       sum(ev.stake_direct.get(a, 0) for a in ev.cibles), len(ev.cibles)))
    if ev.total_staked_reconstruit is not None:
        n_rec = len(ev.stakers_reconstruits or ())
        jambes.append(("rejeu des journaux", ev.total_staked_reconstruit, n_rec))

    if len(jambes) < 2:
        présentes = [n for n, _, _ in jambes]
        return Control("OD-J", OD_J_TITRE, INDISPONIBLE,
                       motif="OD-J exige DEUX jambes de source différente ; "
                             f"{len(jambes)} disponible(s) ({présentes or 'aucune'}). Une seule "
                             "jambe ne distingue plus un cache empoisonné d'un nœud menteur, et un "
                             "contrôle amputé ne doit pas ressembler à un contrôle qui passe "
                             "(KE#76 / KE#105).",
                       observé={"totalStaked_on_chain": str(ev.total_staked_onchain),
                                "jambes": présentes},
                       porte_la_garantie=True)

    écarts = [(nom, somme, somme - ev.total_staked_onchain, n) for nom, somme, n in jambes
              if somme != ev.total_staked_onchain]
    vides = [nom for nom, _, n in jambes if n == 0]
    n_cmp = len(jambes)

    if vides:
        return Control("OD-J", OD_J_TITRE, ECHEC,
                       motif=f"jambe(s) {vides} sur ZÉRO adresse : une somme vide égalerait "
                             f"`totalStaked()` seulement si la chaîne n'a aucun staker, et rendrait "
                             f"l'égalité vacue sinon (KE#111).",
                       observé={"totalStaked_on_chain": str(ev.total_staked_onchain),
                                "jambes_vides": vides},
                       attendu="chaque jambe compare au moins une adresse",
                       comparaisons=n_cmp, porte_la_garantie=True)

    if écarts:
        détail = [f"{nom} : {somme} (écart {d:+d} sur {n} adresse(s))" for nom, somme, d, n in écarts]
        return Control("OD-J", OD_J_TITRE, ECHEC,
                       motif="ÉCART avec la chaîne — " + " ; ".join(détail) + ". Un staker réel est "
                             "absent de l'ensemble de référence (ou un montant ment) : la table ne "
                             "peut PAS être déclarée exhaustive, quoi qu'en disent OD-F et OD-G, "
                             "dont l'ensemble de référence vient du sujet (KE#130).",
                       observé={"totalStaked_on_chain": str(ev.total_staked_onchain),
                                "jambes": {nom: str(somme) for nom, somme, _, _ in écarts},
                                "écart_max": str(max(abs(d) for _, _, d, _ in écarts))},
                       attendu="somme de chaque jambe == totalStaked() au bloc d'instantané",
                       comparaisons=n_cmp, porte_la_garantie=True)

    return Control("OD-J", OD_J_TITRE, OK,
                   observé={"totalStaked_on_chain": str(ev.total_staked_onchain),
                            "jambes": {nom: n for nom, _, n in jambes}},
                   comparaisons=n_cmp, porte_la_garantie=True)


# ====================================================================== vérification HORS LIGNE
#
# Ces contrôles ne dépendent QUE de la table publiée : ni RPC, ni état, ni fenêtre. Ils sont donc
# rejouables par n'importe qui, **pour toujours**, longtemps après que la fenêtre d'état s'est
# refermée. C'est ce qui rend la garantie indépendante de la santé de notre instance.
#
# Ils ne suffisent PAS, et le verdict le dit : ce sont exactement les contrôles que la table à une
# feuille au nom du keeper satisfait. Une portée « table seule » ne vaut jamais feu vert pour une
# ouverture de tirage — elle sert à prouver qu'une table publiée est cohérente avec sa racine, et à
# rejouer nos refus.

TABLE_SEULE_DRAW_IDS = ("OD-A", "OD-B", "OD-C", "OD-E")
TABLE_SEULE_WEEK_IDS = ("PW-A", "PW-B", "PW-D", "PW-E")


def run_table_seule(table):
    """Suite hors ligne. Rend (suite, avertissement) — l'avertissement n'est pas décoratif."""
    if table.kind == "draw":
        s = Suite("openDraw (table seule)", TABLE_SEULE_DRAW_IDS)
        s.add(_root_control("OD-A", table,
                            lambda lf: leaf_draw(lf["player"], lf["weekId"], lf["index"],
                                                 lf["cumulativeFrom"], lf["cumulativeTo"])))
        s.add(_tiling_control(table))
        somme = sum(lf["cumulativeTo"] - lf["cumulativeFrom"] for lf in table.leaves
                    if lf["cumulativeTo"] >= lf["cumulativeFrom"])
        ok = somme == table.total
        s.add(Control("OD-C", "totalWeight == somme des largeurs d'intervalle", OK if ok else ECHEC,
                      motif="" if ok else "un totalWeight gonflé renvoie la part non couverte au Safe.",
                      observé=str(somme), attendu=str(table.total), comparaisons=len(table.leaves)))
        s.add(_dup_control("OD-E", table))
        avert = ("PORTÉE RÉDUITE : les contrôles qui portent la garantie (OD-F exhaustivité, OD-G "
                 "égalité des poids, OD-J somme des stakes == `totalStaked()` on-chain) exigent la "
                 "chaîne et ne sont PAS exécutés ici. Une table à une seule feuille au nom du "
                 "keeper passerait tous les contrôles ci-dessus, et une table qui ampute un staker "
                 "réel aussi. Ce verdict ne vaut donc JAMAIS feu vert pour une ouverture de tirage.")
    else:
        s = Suite("postWeek (table seule)", TABLE_SEULE_WEEK_IDS)
        s.add(_root_control("PW-A", table,
                            lambda lf: leaf_week(lf["player"], lf["weekId"],
                                                 lf["rakebackUsdg"], lf["revshareUsdg"])))
        somme = sum(lf["rakebackUsdg"] + lf["revshareUsdg"] for lf in table.leaves)
        ok = somme == table.total
        s.add(Control("PW-B", "Σ feuilles == totalUsdg", OK if ok else ECHEC,
                      motif="" if ok else "la somme des feuilles ne vaut pas le totalUsdg annoncé.",
                      observé=str(somme), attendu=str(table.total), comparaisons=len(table.leaves)))
        s.add(Control("PW-D", "leafCount == nombre de feuilles",
                      OK if table.leaf_count == len(table.leaves) else ECHEC,
                      observé=table.leaf_count, attendu=len(table.leaves),
                      comparaisons=len(table.leaves)))
        s.add(_dup_control("PW-E", table))
        avert = ("PORTÉE RÉDUITE : `totalUsdg <= funded` (PW-C) et la non-réécriture (PW-F) exigent "
                 "la chaîne et ne sont PAS exécutés ici.")
    return s.seal(), avert
