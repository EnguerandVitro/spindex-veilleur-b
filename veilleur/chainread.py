"""Lectures de chaîne du veilleur : vues du contrat, lectures en masse, et mesure de la fenêtre d'état.

Deux choses méritent d'être dites ici, parce qu'elles décident de l'architecture.

**Multicall3 n'est pas un confort, c'est LA condition de faisabilité.** 100 000 stakers coûtent 10,6 s
par `aggregate3` (4 000 sous-appels par `eth_call`, mesuré 9 446 lectures/s) contre 3 h 23 en appels
unitaires. Or tout doit tenir dans la fenêtre d'état.

**La fenêtre d'état est un paramètre de SÛRETÉ tiré d'une MESURE, donc elle se remesure.** L'atelier 0
l'a relevée deux fois à 30 min d'écart : 6 231 blocs, soit 10 min 28 s. Rien ne garantit qu'un
redéploiement du nœud public ne la change pas. Le veilleur la remesure **à chaque passage** et alerte
si elle descend sous le seuil configuré. Un paramètre de sûreté qu'on ne remesure pas devient une
supposition datée — c'est l'erreur du « DELTA 4 s » tirée de 9 minutes d'échantillon.
"""
import re

from .chainabi import decode_aggregate3, decode_outputs, encode_aggregate3, encode_call
from .rpc import RpcUnavailable

# Formes de refus qui signifient « état élagué », mesurées sur ce nœud (`-32000`).
_PRUNED = re.compile(r"historical state|state .*not available|missing trie node|header not found",
                     re.IGNORECASE)


class ChainReadError(RuntimeError):
    pass


class ChainReader:
    def __init__(self, client, model, settings):
        self.client = client
        self.model = model
        self.s = settings
        self.abi = model.abi
        self.calls = {"multicall": 0, "single": 0, "sous_appels": 0}

    # ------------------------------------------------------------------ vues simples

    def _view(self, fn, args, block):
        data = encode_call(self.abi, fn, args)
        r = self.client.eth_call(self.s.rewards, data, block)
        self.calls["single"] += 1
        if r["kind"] != "ok":
            if r["kind"] == "rpc_error" and _PRUNED.search(r.get("message") or ""):
                raise ChainReadError(
                    f"INDISPONIBLE : l'état du bloc {block} n'est plus servi par ce nœud "
                    f"({r.get('message')}). Hors fenêtre d'état : aucun contrôle ne peut être rendu ici.")
            raise RpcUnavailable(f"{fn}@{block} : {r}")
        return decode_outputs(self.abi, fn, r["result"])

    def total_staked(self, block="latest"):
        return self._view("totalStaked", [], block)

    def stranded_burn(self, block="latest"):
        return self._view("strandedBurn", [], block)

    def free_balance(self, token, block="latest"):
        return self._view("freeBalance", [token], block)

    def prize_reserved(self, token, block="latest"):
        return self._view("prizeReserved", [token], block)

    def week(self, week_id, block="latest"):
        v = self._view("getWeek", [week_id], block)
        keys = ["root", "funded", "claimed_", "fundedAt", "postedAt", "leafCount", "swept"]
        if len(v) != len(keys):
            raise ChainReadError("ARRÊT : getWeek n'a pas rendu le nombre de champs attendu.")
        return dict(zip(keys, v))

    def draw(self, week_id, block="latest"):
        d = self._view("getDraw", [week_id], block)
        if not isinstance(d, dict):
            raise ChainReadError("ARRÊT : getDraw n'a pas rendu une structure.")
        return d

    def max_published_round(self, block="latest"):
        return self._view("maxPublishedRound", [], block)

    # ------------------------------------------------------------------ lectures en masse

    def read_many(self, fn, addresses, block="latest"):
        """Lit `fn(address)` pour TOUTES les adresses, par lots Multicall3.

        Assertions de CARDINAL à chaque étage (KE#111) : autant de résultats que de sous-appels, autant
        de valeurs rendues que d'adresses demandées, et aucun sous-appel en échec toléré. Un lot qui
        rendrait moins de valeurs que demandé ferait silencieusement disparaître des stakers — c'est
        exactement la forme du vol que ce veilleur existe pour empêcher.
        """
        addresses = list(addresses)
        if not addresses:
            raise ChainReadError(
                "ARRÊT : lecture en masse sur ZÉRO adresse. Un résultat vide ne doit pas pouvoir "
                "faire passer un contrôle d'exhaustivité (KE#111).")
        out = {}
        k = max(1, self.s.max_multicall_batch)
        for i in range(0, len(addresses), k):
            chunk = addresses[i:i + k]
            calls = [(self.s.rewards, False, bytes.fromhex(encode_call(self.abi, fn, [a])[2:]))
                     for a in chunk]
            data = encode_aggregate3(calls)
            r = self.client.eth_call(self.s.multicall3, data, block, timeout=180)
            self.calls["multicall"] += 1
            self.calls["sous_appels"] += len(chunk)
            if r["kind"] != "ok":
                if r["kind"] == "rpc_error" and _PRUNED.search(r.get("message") or ""):
                    raise ChainReadError(
                        f"INDISPONIBLE : lecture en masse au bloc {block} refusée — état élagué "
                        f"({r.get('message')}).")
                raise RpcUnavailable(f"aggregate3({fn}) @{block} : {r}")
            res = decode_aggregate3(r["result"], len(chunk))
            for a, (success, ret) in zip(chunk, res):
                if not success:
                    raise ChainReadError(
                        f"ARRÊT : {fn}({a}) a révoqué au bloc {block}. Un sous-appel en échec ne peut "
                        f"pas être lu comme un zéro.")
                out[a] = decode_outputs(self.abi, fn, ret)
        if len(out) != len(set(addresses)):
            raise ChainReadError(
                f"ARRÊT : {len(out)} valeurs pour {len(set(addresses))} adresses demandées.")
        return out

    # ------------------------------------------------------------------ fenêtre d'état

    def verify_multicall3(self):
        """Le Multicall3 configuré doit porter du CODE. Une adresse sans code rendrait `0x` à chaque
        lecture, et `0x` décodé sans garde-fou ressemblerait à « tous les stakes valent zéro »."""
        code = self.client.code_at(self.s.multicall3, "latest")
        if not code or code == "0x":
            raise ChainReadError(
                f"ARRÊT : aucun code à l'adresse Multicall3 configurée ({self.s.multicall3}).")
        return {"adresse": self.s.multicall3, "taille_code_o": (len(code) - 2) // 2}

    def verify_rewards_deployed(self):
        code = self.client.code_at(self.s.rewards, "latest")
        if not code or code == "0x":
            raise ChainReadError(
                f"ARRÊT : aucun code à l'adresse SpindexRewards configurée ({self.s.rewards}). "
                f"Le veilleur ne vérifie pas un contrat qui n'existe pas.")
        return {"adresse": self.s.rewards, "taille_code_o": (len(code) - 2) // 2}

    def _state_available_at(self, block_number):
        """Sonde d'état : une vue du contrat des distributions lui-même — c'est exactement l'état dont
        le contrôle a besoin, pas une doublure.

        Repli DÉCLARÉ : tant que SPINDEX n'est pas déployé, la sonde peut viser une cible tierce
        (`SPINDEX_WINDOW_PROBE_TO` / `_DATA`). C'est alors une doublure de MÊME FORME, et le rapport
        le dit — mesurer sur autre chose que le sujet et ne pas l'écrire serait un chiffre qui ment
        sur sa provenance."""
        to, data = self.window_probe()
        r = self.client.eth_call(to, data, block_number)
        self.calls["single"] += 1
        if r["kind"] == "ok":
            return True
        if r["kind"] == "rpc_error" and _PRUNED.search(r.get("message") or ""):
            return False
        raise RpcUnavailable(
            f"sonde de fenêtre au bloc {block_number} : refus NON attribuable à l'élagage "
            f"({r}). On ne convertit pas une panne en mesure.")

    def window_probe(self):
        to = getattr(self.s, "window_probe_to", None)
        if to:
            return to, getattr(self.s, "window_probe_data", "0x18160ddd")   # totalSupply()
        return self.s.rewards, encode_call(self.abi, "totalStaked", [])

    def window_probe_kind(self):
        """Le label suit la CONFIGURATION, pas une comparaison d'adresses : si une sonde de repli a
        été déclarée, la mesure vient d'une doublure, même si elle pointe par hasard sur la même
        adresse. Un chiffre doit dire d'où il vient, sans exception commode."""
        to, _ = self.window_probe()
        if getattr(self.s, "window_probe_to", None):
            return f"DOUBLURE de même forme déclarée sur {to} (SPINDEX_WINDOW_PROBE_TO)"
        return f"sujet : SpindexRewards.totalStaked() sur {to}"

    def measure_state_window(self, head=None, max_depth=200_000):
        """Dichotomie sur la profondeur d'état encore servie. Rend blocs ET secondes.

        La conversion en secondes passe par une cadence MESURÉE ici, pas par la valeur de l'atelier 0 :
        deux mesures d'un tiers ne se recopient pas l'une l'autre.
        """
        head = head or self.client.block_number()
        if not self._state_available_at(head):
            raise ChainReadError("ARRÊT : même la tête ne sert pas d'état — le nœud n'est pas utilisable.")
        lo = 0                      # profondeur connue OK
        hi = None                   # profondeur connue KO
        probe = 1
        iterations = 0
        while probe <= max_depth:
            iterations += 1
            if self._state_available_at(head - probe):
                lo = probe
                probe *= 2
            else:
                hi = probe
                break
        if hi is None:
            raise ChainReadError(
                f"ARRÊT : aucune profondeur refusée jusqu'à {max_depth} blocs. Ce nœud se comporte comme "
                f"une archive — c'est une bonne nouvelle, mais elle change la règle de temps : à confirmer "
                f"avant de s'y fier.")
        while hi - lo > 1:
            iterations += 1
            mid = (lo + hi) // 2
            if self._state_available_at(head - mid):
                lo = mid
            else:
                hi = mid
        # Assertion de CARDINAL (KE#111) : une dichotomie sans itération ne mesure rien.
        if iterations < 2 or lo + 1 != hi:
            raise ChainReadError("ARRÊT : dichotomie incohérente (itérations={}, lo={}, hi={}).".format(
                iterations, lo, hi))
        cadence = self.measure_block_cadence(head)
        seconds = lo * cadence["secondes_par_bloc"]
        return {
            "sonde": self.window_probe_kind(),
            "tête": head,
            "profondeur_ok_max_blocs": lo,
            "profondeur_ko_min_blocs": hi,
            "itérations": iterations,
            "cadence": cadence,
            "fenêtre_s": round(seconds, 1),
        }

    def measure_block_cadence(self, head=None, span=5000):
        head = head or self.client.block_number()
        if head <= span:
            span = max(1, head // 2)
        t_head = self.client.block_timestamp(head)
        t_old = self.client.block_timestamp(head - span)
        dt = t_head - t_old
        if dt <= 0:
            raise ChainReadError(
                f"ARRÊT : horodatages non croissants sur {span} blocs (Δt = {dt}). "
                f"Toute conversion blocs → secondes serait fausse.")
        return {"span_blocs": span, "delta_s": dt,
                "secondes_par_bloc": dt / span, "blocs_par_s": span / dt}
