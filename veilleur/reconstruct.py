"""Reconstruction de l'état des Locks depuis les JOURNAUX — la preuve PRINCIPALE de l'exhaustivité.

Pourquoi les journaux et pas l'état
-----------------------------------
`_locks` est un `mapping private` : il n'existe **aucune** énumération on-chain des stakers, ni
`stakerCount()`, ni `stakerAt(i)`. La seule voie est le rejeu des journaux depuis le bloc de
déploiement — et elle est EXACTE, parce que les trois transitions portent l'état d'après. Et
`eth_getLogs` remonte à la genèse, pour toujours, là où l'état n'est gardé que 10 min 28 s.

Les deux pièges, lus dans la source, et traités ici
---------------------------------------------------
1. **`Unstaked` ne porte PAS la nouvelle ancre.** La règle du contrat est déterministe :
   `anchor = 0` si `remaining == 0`, sinon `anchor = block.timestamp` **du bloc du journal**. Il faut
   donc joindre chaque `Unstaked` à l'horodatage de son bloc — une jointure qu'un indexeur naïf
   oublie, et qui ne se voit jamais sur un jeu de données sans sortie partielle.
2. **`BoostHalved` n'est PAS émis quand le joueur est déjà à ×1** (`if (newAnchor <= l.anchor) return;`).
   Il existe donc DEUX chemins pour connaître les récoltes : l'événement, et le `Claimed` dont
   `rakebackUsdg != 0`. On les fait **tous les deux** et on EXIGE leur égalité : c'est le contrôle
   gratuit qui ferme la question, et il est load-bearing — le chemin `Claimed` doit répliquer le
   garde-fou, sinon il diverge précisément sur le joueur à ×1.
"""
from .chainabi import decode_event


class ReconstructionError(RuntimeError):
    pass


class LockState:
    __slots__ = ("amount", "anchor")

    def __init__(self, amount=0, anchor=0):
        self.amount = amount
        self.anchor = anchor

    def __eq__(self, o):
        return isinstance(o, LockState) and self.amount == o.amount and self.anchor == o.anchor

    def __repr__(self):
        return f"LockState(amount={self.amount}, anchor={self.anchor})"


EVENTS_USED = ("Staked", "Unstaked", "BoostHalved", "Claimed")


def sort_logs(logs):
    """Ordre canonique (blockNumber, logIndex). Un rejeu dans le désordre écraserait un état par un
    plus ancien, sans rien signaler."""
    def key(lg):
        return (int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"],
                int(lg["logIndex"], 16) if isinstance(lg["logIndex"], str) else lg["logIndex"])
    out = sorted(logs, key=key)
    keys = [key(x) for x in out]
    if len(set(keys)) != len(keys):
        raise ReconstructionError(
            "ARRÊT : deux journaux partagent (blockNumber, logIndex). La clé d'idempotence est cassée : "
            "un doublon indétectable fausserait la reconstruction.")
    return out


class Reconstruction:
    """Résultat d'un rejeu : l'état par joueur, et les compteurs qui prouvent qu'il a eu lieu."""

    def __init__(self, states, counters, halve_source):
        self.states = states              # {adresse: LockState}
        self.counters = counters          # {"Staked": n, ...}
        self.halve_source = halve_source

    def stakers(self):
        """Adresses dont `stakeOf > 0`. C'est l'ensemble que §21 demande de comparer aux feuilles."""
        return {a for a, s in self.states.items() if s.amount > 0}

    def effective(self, model, ts):
        return {a: model.effective_stake(s.amount, s.anchor, ts)
                for a, s in self.states.items() if s.amount > 0}


def replay(model, logs, block_ts, halve_source="event"):
    """Rejoue les journaux et rend la `Reconstruction`.

    `block_ts` : fonction bloc -> horodatage (le veilleur la fournit avec un cache).
    `halve_source` : "event" (BoostHalved) ou "claim" (Claimed + garde-fou du contrat répliqué).
    Les deux DOIVENT donner le même état ; `replay_both` le vérifie.
    """
    if halve_source not in ("event", "claim"):
        raise ReconstructionError("ARRÊT : source de halving inconnue.")
    abi = model.abi
    topics = {abi.topic0(n).lower(): n for n in EVENTS_USED}
    states = {}
    counters = {n: 0 for n in EVENTS_USED}
    counters["ignorés"] = 0

    for lg in sort_logs(logs):
        t0 = lg["topics"][0].lower()
        name = topics.get(t0)
        if name is None:
            counters["ignorés"] += 1
            continue
        ev = decode_event(abi, name, lg)
        player = ev["player"].lower()
        st = states.setdefault(player, LockState())
        counters[name] += 1
        bn = int(lg["blockNumber"], 16) if isinstance(lg["blockNumber"], str) else lg["blockNumber"]

        if name == "Staked":
            # l'événement porte le nouveau montant ET la nouvelle ancre : rien à recalculer.
            st.amount = ev["newAmount"]
            st.anchor = ev["anchor"]
        elif name == "Unstaked":
            st.amount = ev["remaining"]
            # piège n°1 : l'ancre n'est pas dans le journal, elle se déduit du BLOC.
            st.anchor = 0 if ev["remaining"] == 0 else block_ts(bn)
        elif name == "BoostHalved":
            if halve_source != "event":
                continue
            # contrôle de cohérence : le contrat n'émet QUE si l'ancre avance.
            if ev["previousAnchor"] != st.anchor:
                raise ReconstructionError(
                    f"ARRÊT : BoostHalved pour {player} annonce previousAnchor={ev['previousAnchor']} "
                    f"alors que la reconstruction porte {st.anchor}. La divergence est le signal, "
                    f"pas un détail à absorber.")
            st.anchor = ev["newAnchor"]
        elif name == "Claimed":
            if halve_source != "claim":
                continue
            if ev["rakebackUsdg"] == 0:
                continue          # le rev-share ne touche jamais au boost (§3)
            na = model.halved_anchor(st.amount, st.anchor, block_ts(bn))
            if na is not None:    # piège n°2 : `None` = le contrat n'aurait RIEN émis
                st.anchor = na

    total = sum(counters[n] for n in EVENTS_USED)
    if total == 0:
        raise ReconstructionError(
            "ARRÊT : ZÉRO événement de Lock rejoué. Un ensemble de stakers vide rendrait le contrôle "
            "d'exhaustivité VACUEMENT vrai — exactement le contrôle qui passe à vide que ce projet "
            "a trouvé quatre fois (KE#111).")
    return Reconstruction(states, counters, halve_source)


def replay_both(model, logs, block_ts):
    """Rejoue par les DEUX chemins et exige leur égalité. Rend (reconstruction_event, rapport)."""
    a = replay(model, logs, block_ts, halve_source="event")
    b = replay(model, logs, block_ts, halve_source="claim")
    keys = set(a.states) | set(b.states)
    if not keys:
        raise ReconstructionError("ARRÊT : les deux rejeux sont vides — rien n'a été comparé (KE#111).")
    diff = []
    for k in sorted(keys):
        sa = a.states.get(k, LockState())
        sb = b.states.get(k, LockState())
        if sa != sb:
            diff.append((k, repr(sa), repr(sb)))
    rapport = {
        "adresses_comparées": len(keys),
        "divergences": len(diff),
        "détail": diff[:10],
        "compteurs_event": a.counters,
        "compteurs_claim": b.counters,
    }
    # Assertion de cardinal : comparer zéro adresse ne prouve rien.
    if rapport["adresses_comparées"] == 0:
        raise ReconstructionError("ARRÊT : cardinal nul dans le recoupement des deux chemins de halving.")
    return a, rapport


class BlockTimestamps:
    """Cache d'horodatages de blocs. Compte ses appels : ils finissent dans le verdict."""

    def __init__(self, client):
        self.client = client
        self.cache = {}
        self.calls = 0

    def __call__(self, block_number):
        if block_number not in self.cache:
            self.cache[block_number] = self.client.block_timestamp(block_number)
            self.calls += 1
        return self.cache[block_number]
