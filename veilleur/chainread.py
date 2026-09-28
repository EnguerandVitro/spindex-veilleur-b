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
from .chainabi import (SEL_TOTAL_SUPPLY, decode_aggregate3, decode_outputs, encode_aggregate3,
                       encode_call)
from .fournisseurs import CLASSES_SANS_ETAT, PROFONDEUR_MAX_DEFAUT, TEMOIN_AVANCE_BLOCS, classer
from .rpc import RpcUnavailable


def _sans_etat(r):
    """« Ce nœud ne sert pas d'état à ce bloc » — décidé sur une signature MESURÉE, pas sur une
    expression régulière écrite de mémoire (`fournisseurs.SIGNATURES`). Couvre l'état élagué
    (`historical state …`, `missing trie node …`) et le bloc inexistant (`header not found`,
    `unsupported block number …`, `Unknown block`), qui viennent chacun d'un fournisseur différent."""
    return classer(r)[0] in CLASSES_SANS_ETAT


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
            if _sans_etat(r):
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
                if _sans_etat(r):
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
        if _sans_etat(r):
            return False
        raise RpcUnavailable(
            f"sonde de fenêtre au bloc {block_number} : refus NON attribuable à l'élagage "
            f"({r}). On ne convertit pas une panne en mesure.")

    def window_probe(self):
        to = getattr(self.s, "window_probe_to", None)
        if to:
            return to, getattr(self.s, "window_probe_data", SEL_TOTAL_SUPPLY)   # totalSupply()
        return self.s.rewards, encode_call(self.abi, "totalStaked", [])

    def window_probe_kind(self):
        """Le label suit la CONFIGURATION, pas une comparaison d'adresses : si une sonde de repli a
        été déclarée, la mesure vient d'une doublure, même si elle pointe par hasard sur la même
        adresse. Un chiffre doit dire d'où il vient, sans exception commode."""
        to, _ = self.window_probe()
        if getattr(self.s, "window_probe_to", None):
            return f"DOUBLURE de même forme déclarée sur {to} (SPINDEX_WINDOW_PROBE_TO)"
        return f"sujet : SpindexRewards.totalStaked() sur {to}"

    def sonde_sait_dire_non(self, head):
        """TÉMOIN POSITIF de la sonde (KE#121) — obligatoire AVANT toute mesure de fenêtre.

        « La fenêtre vaut au moins X » est une INÉGALITÉ : elle est satisfaite par la PANNE du côté
        sous test. Une sonde qui répondrait « état disponible » à tout, quelle que soit la
        profondeur, rendrait une fenêtre infinie et un feu vert permanent — c'est exactement ce que
        fait un nœud d'ARCHIVE, et c'est exactement ce que ferait une sonde cassée. On ne peut pas
        distinguer les deux sans forcer la sonde à dire NON au moins une fois.

        Le bloc témoin est en AVANCE sur la tête : il ne peut porter aucun état, sur aucun nœud,
        archive ou non. Tout refus fait l'affaire — les trois fournisseurs mesurés le formulent
        différemment (`unsupported block number …`, `header not found`, `Unknown block` en HTTP 400).
        La seule réponse inadmissible est un SUCCÈS.
        """
        bloc = head + TEMOIN_AVANCE_BLOCS
        to, data = self.window_probe()
        r = self.client.eth_call(to, data, bloc)
        self.calls["single"] += 1
        if r["kind"] == "ok":
            raise ChainReadError(
                f"ARRÊT : la sonde de fenêtre répond « état disponible » au bloc {bloc}, soit "
                f"{TEMOIN_AVANCE_BLOCS} blocs DEVANT la tête ({head}) — un bloc que la chaîne n'a pas "
                f"atteint. Une sonde qui ne sait pas dire non ne mesure rien, et toute fenêtre "
                f"qu'elle rendrait serait une fiction (KE#121).")
        classe, _sig = classer(r)
        if classe not in CLASSES_SANS_ETAT:
            # « N'importe quel refus » ne vaut PAS témoin : une limitation de débit, une panne de
            # transport ou un refus jamais mesuré arrivent aussi ici, et aucun ne prouve que la sonde
            # sache distinguer un bloc sans état d'un bloc avec état. Le témoin ne doit pas pouvoir
            # être satisfait par une panne DU NŒUD non plus (KE#121 au second degré).
            raise ChainReadError(
                f"ARRÊT : au bloc témoin {bloc} le nœud a répondu un refus de classe « {classe} », pas "
                f"« ce bloc n'a pas d'état ». Ce n'est pas un témoin : la sonde n'a rien prouvé. "
                f"Réponse : {str(r.get('message') or r.get('body'))[:200]}")
        return {"bloc": bloc, "refus": classe, "détail": str(r.get("message") or r.get("body"))[:160]}

    def measure_state_window(self, head=None, max_depth=None):
        """Dichotomie sur la profondeur d'état encore servie. Rend blocs ET secondes.

        La conversion en secondes passe par une cadence MESURÉE ici, pas par la valeur de l'atelier 0 :
        deux mesures d'un tiers ne se recopient pas l'une l'autre.

        **Nœud d'ARCHIVE (mesuré sur dRPC le 2026-09-24).** Une profondeur « infinie » faisait
        échouer cette recherche : la boucle de doublement ne trouvait jamais de profondeur refusée,
        `hi` restait None et la mesure s'arrêtait — trois sondes en échec sur trois, donc
        `fenêtre_non_mesurée`, sur le nœud le PLUS généreux des trois. Une recherche qui suppose une
        borne ne peut pas mesurer ce qui n'en a pas. Elle rend désormais un **MINORANT** déclaré
        (`borne = "minorant"`), qui dit ce qu'il est : « au moins {max_depth} blocs », jamais « exactement ».

        Le minorant n'est recevable que parce que `sonde_sait_dire_non` a été exercé juste avant :
        sans ce témoin, « au moins N » serait aussi ce que rendrait une sonde en panne.
        """
        max_depth = int(max_depth if max_depth is not None
                        else getattr(self.s, "window_max_depth", PROFONDEUR_MAX_DEFAUT))
        head = head or self.client.block_number()
        temoin = self.sonde_sait_dire_non(head)
        if not self._state_available_at(head):
            raise ChainReadError("ARRÊT : même la tête ne sert pas d'état — le nœud n'est pas utilisable.")
        # Jamais de bloc négatif : sur une chaîne courte (banc, anvil neuf) la tête EST le plafond.
        plafond = min(max_depth, head)
        if plafond < 1:
            raise ChainReadError(
                f"ARRÊT : tête {head} — il n'y a pas un bloc de profondeur à sonder. Aucune fenêtre "
                f"ne peut être mesurée sur cette chaîne.")
        lo = 0                      # profondeur connue OK
        hi = None                   # profondeur connue KO
        probe = 1
        iterations = 0
        while True:
            iterations += 1
            if not self._state_available_at(head - probe):
                hi = probe
                break
            lo = probe
            if probe >= plafond:
                break
            probe = min(probe * 2, plafond)
        cadence = self.measure_block_cadence(head)
        if hi is None:
            # ARCHIVE : aucune profondeur refusée jusqu'au plafond. Ce n'est pas un échec de mesure,
            # c'est une mesure d'une autre NATURE — et elle le dit dans `borne`.
            if lo != plafond or iterations < 1:
                raise ChainReadError(
                    f"ARRÊT : minorant incohérent (lo={lo}, plafond={plafond}, itérations={iterations}).")
            return {
                "sonde": self.window_probe_kind(),
                "témoin": temoin,
                "tête": head,
                "borne": "minorant",
                "profondeur_ok_max_blocs": lo,
                "profondeur_ko_min_blocs": None,
                "itérations": iterations,
                "cadence": cadence,
                "fenêtre_s": round(lo * cadence["secondes_par_bloc"], 1),
                "à_savoir": f"nœud d'ARCHIVE : l'état est encore servi à {lo} blocs de profondeur, "
                            f"la sonde n'a trouvé aucune limite. La valeur rendue est un MINORANT, "
                            f"pas la fenêtre — elle ne peut pas servir de référence de dérive.",
            }
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
        seconds = lo * cadence["secondes_par_bloc"]
        return {
            "sonde": self.window_probe_kind(),
            "témoin": temoin,
            "tête": head,
            "borne": "exacte",
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
