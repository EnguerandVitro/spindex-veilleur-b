"""Comptabilité du burn de sortie (§19 / §22) — contrôle BLOQUANT, pas un indicateur.

`en attente = Σ ExitBurnDeferred.amount − Σ ExitBurnFlushed.amount` doit égaler EXACTEMENT
`strandedBurn` lu on-chain. Égalité exacte depuis la v4 ; tout écart est un journal manqué, donc une
base trouée, donc un veilleur qui donnerait une garantie fausse. Alerte bruyante et arrêt de la
publication (KE#105).

La ligne « détruit » est reconstituée à côté, et elle ne se somme jamais avec la précédente :

    détruit = Σ Unstaked.burned − Σ ExitBurnDeferred.amount + Σ ExitBurnFlushed.amount
              + Σ (BurnMismatch.burned − BurnMismatch.requested) sur les seuls cas burned > requested

`Unstaked.burned` porte le montant **VISÉ**, pas le détruit, et il est émis même quand le burn a
échoué. Le sommer seul SURESTIME la destruction pendant toute une pause de l'émetteur — c'est-à-dire
exactement au moment où le chiffre serait le plus regardé.

`BurnMismatch` n'a AUCUN champ indexé : il ne se corrèle qu'à l'`Unstaked` / `flushExitBurn` de la
MÊME transaction. On conserve donc `transactionHash` et `logIndex` de chaque occurrence.
"""
from .chainabi import decode_event
from .controls import Control, ECHEC, INDISPONIBLE, OK

EVENTS = ("ExitBurnDeferred", "ExitBurnFlushed", "BurnMismatch", "Unstaked")


def collect(model, logs):
    """Agrège les journaux du burn. Rend les sommes ET les compteurs qui prouvent l'agrégation."""
    abi = model.abi
    topics = {abi.topic0(n).lower(): n for n in EVENTS}
    sums = {"deferred": 0, "flushed": 0, "unstaked_burned": 0, "mismatch_excess": 0}
    counts = {n: 0 for n in EVENTS}
    mismatches = []
    for lg in logs:
        name = topics.get(lg["topics"][0].lower())
        if name is None:
            continue
        ev = decode_event(abi, name, lg)
        counts[name] += 1
        if name == "ExitBurnDeferred":
            sums["deferred"] += ev["amount"]
        elif name == "ExitBurnFlushed":
            sums["flushed"] += ev["amount"]
        elif name == "Unstaked":
            sums["unstaked_burned"] += ev["burned"]
        elif name == "BurnMismatch":
            # le trop-détruit : le seul terme que `ExitBurnDeferred` ne porte pas.
            if ev["burned"] > ev["requested"]:
                sums["mismatch_excess"] += ev["burned"] - ev["requested"]
            mismatches.append({
                "transactionHash": lg.get("transactionHash"),
                "logIndex": lg.get("logIndex"),
                "requested": str(ev["requested"]),
                "burned": str(ev["burned"]),
            })
    return sums, counts, mismatches


def control(model, logs, stranded_onchain, cid="LB-A"):
    """Le contrôle bloquant. `stranded_onchain` doit être lu AU MÊME BLOC que les journaux."""
    sums, counts, mismatches = collect(model, logs)
    if stranded_onchain is None:
        return Control(cid, "Σ Deferred − Σ Flushed == strandedBurn", INDISPONIBLE,
                       motif="`strandedBurn` n'a pas pu être lu on-chain."), {}
    attendu = sums["deferred"] - sums["flushed"]
    n_mouvements = counts["ExitBurnDeferred"] + counts["ExitBurnFlushed"]
    détruit = (sums["unstaked_burned"] - sums["deferred"] + sums["flushed"] + sums["mismatch_excess"])
    lignes = {
        "en_attente_reconstitué": str(attendu),
        "strandedBurn_on_chain": str(stranded_onchain),
        "détruit_reconstitué": str(détruit),
        "Σ_Unstaked_burned_visé": str(sums["unstaked_burned"]),
        "Σ_ExitBurnDeferred": str(sums["deferred"]),
        "Σ_ExitBurnFlushed": str(sums["flushed"]),
        "Σ_trop_détruit_BurnMismatch": str(sums["mismatch_excess"]),
        "compteurs": counts,
        "mismatches": mismatches[:20],
        # Les deux lignes ne se somment JAMAIS : le tableau de bord les affiche séparément.
        "note": "« en attente » et « détruit » sont deux lignes distinctes ; leur somme n'a aucun sens.",
    }
    if attendu != stranded_onchain:
        c = Control(cid, "Σ Deferred − Σ Flushed == strandedBurn", ECHEC,
                    motif=f"écart de {attendu - stranded_onchain} unités. Un écart = un journal manqué = "
                          f"une base trouée. Publier sur une base trouée donnerait une garantie fausse.",
                    observé=lignes, attendu="égalité exacte", comparaisons=max(1, n_mouvements))
    elif n_mouvements == 0:
        # Vacuité NOMMÉE : l'égalité 0 == 0 est vraie, mais elle n'a rien exercé. Le dire est la seule
        # façon de ne pas faire passer une absence de données pour une comptabilité vérifiée (KE#111).
        c = Control(cid, "Σ Deferred − Σ Flushed == strandedBurn", OK,
                    motif="VACUE : aucun mouvement de burn différé à ce jour. L'égalité est vérifiée "
                          "contre la chaîne (0 == 0) mais elle n'exerce aucun agrégat.",
                    observé=lignes, comparaisons=1)
        c.vacuité = True
    else:
        c = Control(cid, "Σ Deferred − Σ Flushed == strandedBurn", OK,
                    observé=lignes, comparaisons=n_mouvements)
    return c, lignes
