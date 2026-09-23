"""Historique des mesures de fenêtre d'état, et gravité jugée contre le BESOIN de sûreté.

Ce que la fenêtre protège
-------------------------
La règle de temps de l'arbitrage Q2-3 (``backend/ATELIERS.md`` §Q2 point 3, rappelée dans
``rapports/veilleur.md`` §6) : l'exploitant publie la table **dans les 8 minutes** qui suivent le bloc
d'instantané, et le veilleur vérifie par lecture directe **à l'intérieur** de la fenêtre d'état. Le
BESOIN de sûreté est donc de 480 s (``BESOIN_DEFAUT_S``, surchargeable par
``SPINDEX_WINDOW_NEED_S``). La consigne d'exploitation resserrée à 5 min (``SPINDEX_PUBLISH_DEADLINE_S``)
est plus stricte que le besoin, elle ne le remplace pas.

Quatre alertes, et elles ne disent pas la même chose (arbitrage du coordinateur, 2026-09-22) :

  `fenêtre_sous_besoin`       — P0 : fenêtre < 1 × besoin. Une table publiée à l'échéance de la règle
                                des 8 minutes n'est plus vérifiable par lecture directe : le contrôle
                                normatif de §21 ne peut plus être rendu.
  `fenêtre_en_recul`          — P1 : la fenêtre a perdu plus de `tolerance_bps` par rapport à la
                                meilleure relevée ET elle est sous 1,5 × besoin. Le recul est réel et la
                                marge qui reste ne le laisse plus passer pour du bruit.
  `fenêtre_recul_sans_risque` — P2 : même recul, mais la fenêtre reste ≥ 1,5 × besoin. Signalé (la
                                meilleure, la courante, le multiple du besoin), jamais tu, jamais P1 :
                                la gravité se juge contre le besoin, pas contre un record.
  `fenêtre_sous_seuil`        — avertissement permanent : sous le seuil de consigne
                                (``SPINDEX_WINDOW_ALERT_S``, 720 s = 1,5 × 480 s). Le seuil de consigne et
                                la limite P1 coïncident par construction ; une configuration qui mettrait le
                                seuil SOUS le besoin est refusée au chargement (``config.py``).

Pourquoi la meilleure valeur était trompeuse sur la 46630 : l'URL publique répond par PLUSIEURS nœuds
(KE#133), qui ne servent pas tous la même profondeur d'état (6 208 blocs sur l'un, 8 596 sur l'autre à
cinq minutes d'écart, relevé dans ``fenetre.json``). Une « meilleure jamais relevée » lue sur le nœud
généreux fait crier en P1 chaque passe servie par le nœud avare. D'où deux corrections :

  * la mesure de sûreté est le MINIMUM de ``SONDES_MIN`` (3) sondes indépendantes, chacune sur ses
    propres requêtes (``mesurer_fenetre``), et les sondes sont exposées une à une ;
  * la référence « meilleure » ne se calcule QUE sur des mesures de même nature (minimum d'au moins
    3 sondes). Les mesures d'avant, à sonde unique, sont conservées dans le fichier mais comptées à
    part : les comparer à un minimum mettrait un maximum de fait en référence.
"""
import json
import os
import time

from .chainread import ChainReadError
from .rpc import RpcUnavailable

# Règle des 8 minutes de publication (arbitrage Q2-3) : ce que la fenêtre d'état doit couvrir.
BESOIN_DEFAUT_S = 480
# Limite P1 : 1,5 × besoin, écrite en fraction entière (pas de flottant dans une comparaison de sûreté).
MULTIPLE_P1 = (3, 2)
# Nombre de sondes indépendantes dont on prend le minimum (KE#133 : plusieurs nœuds, lectures non monotones).
SONDES_MIN = 3
AGREGAT = "minimum"


def mesurer_fenetre(reader, head=None, sondes=SONDES_MIN, tentatives_max=None):
    """Mesure de SÛRETÉ de la fenêtre : minimum de ``sondes`` mesures indépendantes (≥ ``SONDES_MIN``).

    Chaque sonde est une dichotomie complète (``reader.measure_state_window``) sur ses propres requêtes :
    derrière une URL publique à plusieurs nœuds, deux sondes peuvent tomber sur deux nœuds différents, et
    la fenêtre utilisable est celle du plus avare. Une sonde en échec est COMPTÉE et exposée ; il faut
    ``sondes`` réussites en au plus ``tentatives_max`` essais (défaut 2 × sondes), sinon la mesure est
    refusée (``ChainReadError``) — jamais un minimum pris sur moins de sondes que promis (KE#111).
    """
    if sondes < SONDES_MIN:
        raise ValueError(f"ARRÊT : {sondes} sonde(s) demandée(s), minimum {SONDES_MIN} (KE#133).")
    tentatives_max = tentatives_max or 2 * sondes
    reussies, echecs, essais = [], [], 0
    while essais < tentatives_max and len(reussies) < sondes:
        essais += 1
        try:
            w = reader.measure_state_window(head=head)
        except (ChainReadError, RpcUnavailable) as e:
            echecs.append(f"{type(e).__name__}: {e}"[:300])
            continue
        if w.get("fenêtre_s") is None or w.get("profondeur_ok_max_blocs") is None:
            echecs.append("sonde sans fenêtre_s / profondeur")
            continue
        reussies.append(w)
    if len(reussies) < sondes:
        raise ChainReadError(
            f"ARRÊT : {len(reussies)} sonde(s) de fenêtre réussie(s) sur {sondes} exigées en {essais} "
            f"essai(s) : la mesure de sûreté n'est pas rendue sur moins de sondes que promis. "
            f"Échecs : {echecs}")
    retenue = min(reussies, key=lambda w: w["fenêtre_s"])
    out = dict(retenue)
    out.update({
        "fenêtre_s": min(w["fenêtre_s"] for w in reussies),
        "profondeur_ok_max_blocs": min(w["profondeur_ok_max_blocs"] for w in reussies),
        "agrégat": AGREGAT,
        "n_sondes": len(reussies),
        "sondes": [{"tête": w.get("tête"), "profondeur_ok_max_blocs": w["profondeur_ok_max_blocs"],
                    "fenêtre_s": w["fenêtre_s"],
                    "secondes_par_bloc": (w.get("cadence") or {}).get("secondes_par_bloc")}
                   for w in reussies],
        "sondes_en_échec": echecs,
        "écart_sondes_s": round(max(w["fenêtre_s"] for w in reussies)
                                - min(w["fenêtre_s"] for w in reussies), 1),
    })
    return out


def _agregee(m):
    return m.get("agrégat") == AGREGAT and (m.get("n_sondes") or 0) >= SONDES_MIN


class WindowHistory:
    def __init__(self, state_dir, name="fenetre.json", max_entries=500):
        self.path = os.path.join(state_dir, name)
        self.max_entries = max_entries
        self.data = {"mesures": []}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        self.data.setdefault("mesures", [])

    @property
    def meilleure_s(self):
        """Meilleure fenêtre relevée PARMI les mesures agrégées (minimum d'au moins 3 sondes) seulement."""
        vals = [m["fenêtre_s"] for m in self.data["mesures"] if m.get("fenêtre_s") and _agregee(m)]
        return max(vals) if vals else None

    @property
    def mesures_mono_sonde_ignorees(self):
        return sum(1 for m in self.data["mesures"] if m.get("fenêtre_s") and not _agregee(m))

    def ajouter(self, mesure):
        self.data["mesures"].append({
            "ts": int(time.time()),
            "tête": mesure.get("tête"),
            "blocs": mesure.get("profondeur_ok_max_blocs"),
            "fenêtre_s": mesure.get("fenêtre_s"),
            "sonde": mesure.get("sonde"),
            "agrégat": mesure.get("agrégat"),
            "n_sondes": mesure.get("n_sondes"),
            "sondes_s": [x.get("fenêtre_s") for x in (mesure.get("sondes") or [])],
        })
        self.data["mesures"] = self.data["mesures"][-self.max_entries:]
        return self

    def alertes(self, mesure, seuil_absolu_s, *, besoin_s, tolerance_bps=500):
        """Rend la liste des alertes. ``besoin_s`` est OBLIGATOIRE et nommé (KE#62) : la gravité se juge
        contre lui, et un appelant qui l'oublierait retomberait sur un jugement contre le record."""
        out = []
        f = mesure.get("fenêtre_s")
        if f is None:
            return [{"gravité": "P1", "source": "fenêtre d'état", "clé": "fenêtre_non_mesurée",
                     "motif": "fenêtre non mesurée — « je n'ai pas pu mesurer » n'est pas « tout va bien »."}]
        if not _agregee(mesure):
            # La gravité ne se juge que sur la mesure de SÛRETÉ (minimum de ≥ 3 sondes). Une mesure à sonde
            # unique dépend du nœud qui a répondu : elle ne vaut ni feu vert ni incident.
            return [{"gravité": "P1", "source": "fenêtre d'état", "clé": "fenêtre_non_agrégée",
                     "motif": f"mesure de fenêtre à {mesure.get('n_sondes') or 1} sonde(s), agrégat "
                              f"{mesure.get('agrégat')!r} : la sûreté exige le minimum d'au moins "
                              f"{SONDES_MIN} sondes (KE#133). Non jugée."}]
        num, den = MULTIPLE_P1
        multiple = round(f / besoin_s, 2)
        if f < besoin_s:
            out.append({
                "gravité": "P0", "source": "fenêtre d'état", "clé": "fenêtre_sous_besoin",
                "motif": f"fenêtre mesurée {f} s (minimum de {mesure['n_sondes']} sondes) < besoin "
                         f"{besoin_s} s (règle des 8 minutes de publication) : ×{multiple} du besoin.",
                "conséquence": "une table publiée dans les délais de la règle n'est plus vérifiable par "
                               "lecture directe : le contrôle normatif de §21 ne peut plus être rendu.",
                "fenêtre_s": f, "besoin_s": besoin_s, "multiple_du_besoin": multiple,
            })
        if f < seuil_absolu_s:
            out.append({
                "gravité": "AVERTISSEMENT_PERMANENT", "source": "fenêtre d'état",
                "clé": "fenêtre_sous_seuil",
                "motif": f"fenêtre mesurée {f} s < seuil de consigne {seuil_absolu_s} s "
                         f"(×{multiple} du besoin de {besoin_s} s).",
                "à_savoir": "avertissement permanent, pas un incident : la GRAVITÉ se juge contre le besoin "
                            "(P0 sous 1 × besoin, P1 si recul sous 1,5 × besoin). Le seuil de consigne vaut "
                            "par défaut 1,5 × besoin, la zone où un recul devient P1.",
            })
        ref = self.meilleure_s
        if ref is None:
            out.append({
                "gravité": "INFO", "source": "fenêtre d'état", "clé": "pas_d_historique",
                "motif": "aucune mesure agrégée antérieure : aucune dérive n'est calculable. Ce n'est pas "
                         "« pas de dérive », c'est « pas encore de référence » (KE#111)"
                         + (f" ; {self.mesures_mono_sonde_ignorees} mesure(s) à sonde unique ignorée(s) "
                            f"comme référence (KE#133)." if self.mesures_mono_sonde_ignorees else "."),
            })
        elif f * 10_000 < ref * (10_000 - tolerance_bps):
            recul = round((1 - f / ref) * 100, 2)
            detail = {"meilleure_s": ref, "courante_s": f, "besoin_s": besoin_s,
                      "multiple_du_besoin": multiple, "recul_pct": recul,
                      "limite_p1_s": besoin_s * num / den}
            if f * den < besoin_s * num:
                out.append({
                    "gravité": "P1", "source": "fenêtre d'état", "clé": "fenêtre_en_recul",
                    "motif": f"la fenêtre est passée de {ref} s (meilleure relevée) à {f} s, soit {recul} % "
                             f"de recul, et elle n'est plus qu'à ×{multiple} du besoin de {besoin_s} s "
                             f"(< ×1,5).",
                    "conséquence": "la règle des 8 minutes de publication se rapproche de l'inexécutable ; "
                                   "sous le besoin, le contrôle normatif de §21 ne peut plus être rendu.",
                    **detail,
                })
            else:
                out.append({
                    "gravité": "P2", "source": "fenêtre d'état", "clé": "fenêtre_recul_sans_risque",
                    "motif": f"recul de {recul} % ({ref} s → {f} s), mais la fenêtre reste à ×{multiple} du "
                             f"besoin de {besoin_s} s (≥ ×1,5) : signalé, pas un incident.",
                    **detail,
                })
        return out

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        return self.path


class DureeHistory:
    """Durées de vérification OBSERVÉES, et le délai maximal de publication qui s'en DÉRIVE.

    Le coordinateur a tranché : le délai admis entre le bloc d'instantané et la vérification ne se
    CHOISIT pas, il se calcule —

        délai_max_admis = fenêtre_mesurée − 3 × durée de vérification observée

    Les deux termes sont des mesures, et les deux sont re-mesurés. Le facteur 3 est la marge : il
    faut pouvoir rater deux passes et réussir la troisième **à l'intérieur** de la fenêtre.

    La durée retenue est le **maximum observé**, pas une moyenne. Une borne de sûreté tirée d'une
    moyenne se fait battre une fois sur deux ; et le nombre d'observations est publié avec le
    chiffre, parce qu'un maximum sur trois passes ne vaut pas un maximum sur trois cents
    (« borne de sûreté ≠ max d'un échantillon court » — tant que N est petit, le chiffre est une
    indication, et il le DIT).
    """

    MARGE = 3

    def __init__(self, state_dir, name="durees.json", max_entries=500):
        self.path = os.path.join(state_dir, name)
        self.max_entries = max_entries
        self.data = {"durées": []}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)
        self.data.setdefault("durées", [])

    @property
    def n(self):
        return len(self.data["durées"])

    @property
    def max_s(self):
        vals = [d["s"] for d in self.data["durées"] if d.get("s")]
        return max(vals) if vals else None

    def ajouter(self, secondes, portée=""):
        self.data["durées"].append({"ts": int(time.time()), "s": round(float(secondes), 3),
                                    "portée": portée})
        self.data["durées"] = self.data["durées"][-self.max_entries:]
        return self

    def delai_max_admis(self, fenetre_s):
        """Rend le délai DÉRIVÉ, ou une explication de pourquoi il ne l'est pas. Jamais un défaut muet."""
        if fenetre_s is None:
            return {"dérivé": False, "pourquoi": "fenêtre d'état non mesurée à cette passe."}
        d = self.max_s
        if d is None:
            return {"dérivé": False,
                    "pourquoi": "aucune durée de vérification observée : le délai ne peut pas être "
                                "dérivé. Ce n'est pas « pas de limite », c'est « pas encore "
                                "mesurable » (KE#111).",
                    "fenêtre_s": fenetre_s}
        val = fenetre_s - self.MARGE * d
        return {
            "dérivé": True,
            "délai_max_admis_s": round(val, 1),
            "formule": "fenêtre_mesurée − 3 × durée_de_vérification_max_observée",
            "fenêtre_s": fenetre_s,
            "durée_max_observée_s": d,
            "observations": self.n,
            "fiabilité": ("indicative : échantillon court" if self.n < 30
                          else "établie sur un échantillon suffisant"),
            "utilisable": val > 0,
            "si_négatif": ("une valeur négative signifie que la vérification ne tient PLUS dans la "
                           "fenêtre avec sa marge : aucun instantané ne peut plus être vérifié à "
                           "temps, et c'est un incident, pas un réglage."),
        }

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        return self.path
