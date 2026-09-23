"""Client JSON-RPC **en lecture seule** du veilleur.

Constitutif, pas décoratif : ce qui vérifie ne doit pas pouvoir signer. La liste blanche de méthodes
ci-dessous est la forme exécutable de cette règle — `eth_sendRawTransaction`, `eth_sendTransaction`,
`eth_sign`, `personal_*`, `eth_signTransaction`, `eth_accounts` ne sont pas « déconseillés », ils sont
IMPOSSIBLES à émettre depuis ce client, et un appelant qui essaie obtient une exception, pas un refus
silencieux. Un test de cassure le prouve.

Séparation transport / applicatif (leçon du 2026-09-20) : un `403`, un `429`, un `502` ou un délai
dépassé ne peuvent jamais se lire comme « la chaîne est vide ». Chaque appel rend
`{kind: ok | rpc_error | http | transport}` et aucun consommateur n'a le droit de confondre
`rpc_error` et `ok`. Les 429 sont COMPTÉS : un 429 absorbé en silence est une panne déguisée en heure
calme (KE#105).

Mesure de l'atelier 0 reprise telle quelle : le 429 de ce nœud arrive avec un **statut HTTP 429** ET
un corps qui a la FORME d'une erreur JSON-RPC. Les deux chemins sont traités.
"""
import json
import random
import re
import time
import urllib.error
import urllib.request

# Liste BLANCHE. Toute méthode absente est refusée côté client, avant le réseau.
READ_ONLY_METHODS = frozenset({
    "eth_blockNumber",
    "eth_chainId",
    "eth_call",
    "eth_getBalance",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getCode",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockReceipts",
    "eth_feeHistory",
    "net_version",
    "web3_clientVersion",
})

# Nommées pour que le message d'erreur soit un enseignement, pas une énigme.
FORBIDDEN_METHODS = frozenset({
    "eth_sendTransaction", "eth_sendRawTransaction", "eth_signTransaction", "eth_sign",
    "eth_signTypedData", "eth_signTypedData_v4", "eth_accounts", "eth_requestAccounts",
    "personal_sign", "personal_sendTransaction", "personal_unlockAccount", "miner_start",
})


# Erreurs de TAILLE de plage explicitement reconnues pour `eth_getLogs`. C'est la SEULE cause qui autorise à
# découper une plage. Un 429 n'est pas une plage trop large : découper sur un 429 multiplie les appels au moment
# précis où le nœud demande d'en faire moins (mesuré le 2026-09-21 : 16 tranches sur 40 en échec sur un contrat
# actif, avec l'ancien code qui divisait la plage par 4). Le message de ce nœud ment sur sa nature
# (« limit of 10000 » est une limite de PLAGE) : il est reconnu ici tel qu'il est.
ERREUR_DE_PLAGE = re.compile(
    r"(block range|range (is )?too (large|wide|big)|limit of \d+|query returned more than|"
    r"too many (results|logs|blocks)|exceed(s|ed)? (the )?(max|limit|range)|response size)",
    re.IGNORECASE)


def est_erreur_de_plage(r):
    return r.get("kind") == "rpc_error" and bool(ERREUR_DE_PLAGE.search(str(r.get("message") or "")))


def _retry_after(v):
    """`Retry-After` en secondes (entier ou décimal) ; une date HTTP n'est pas interprétée (None)."""
    try:
        x = float(str(v).strip())
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


class RpcRefused(RuntimeError):
    """Le client a refusé d'émettre : méthode hors lecture seule."""


class RpcUnavailable(RuntimeError):
    """Le RPC n'a pas répondu utilement. JAMAIS à confondre avec « rien à signaler »."""


class RpcClient:
    # Sur 429 : attente, JAMAIS de découpage. `Retry-After` respecté s'il est présent (plafonné), sinon repli
    # exponentiel borné. Le total d'attente par appel est borné aussi : au-delà, l'appel ÉCHOUE bruyamment.
    ATTENTE_429_INITIALE_S = 0.5
    ATTENTE_429_MAX_S = 30.0
    ESSAIS_429_MAX = 8
    ATTENTE_429_TOTALE_MAX_S = 120.0

    def __init__(self, url, timeout=120, max_retries=4, user_agent="spindex-veilleur/1 (read-only)"):
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.ua = user_agent
        self._sleep = time.sleep
        self.stats = {"calls": 0, "http": {}, "transport": 0, "rpc_error": 0, "http_429": 0, "retries": 0,
                      "attente_429_s": 0.0, "plages_découpées": 0}

    # ------------------------------------------------------------------ transport

    def _post(self, payload, timeout=None):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url, method="POST", data=body,
            headers={"content-type": "application/json", "user-agent": self.ua})
        self.stats["calls"] += 1
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                raw = r.read()
                self.stats["http"][r.status] = self.stats["http"].get(r.status, 0) + 1
            d = json.loads(raw)
            # 429 servi avec un statut 200 et un corps en forme d'erreur JSON-RPC : mesuré sur ce nœud.
            if isinstance(d, dict) and "error" in d:
                code = d["error"].get("code")
                if code == 429:
                    self.stats["http_429"] += 1
                    return {"kind": "http", "status": 429,
                            "body": str(d["error"].get("message"))[:250], "dt": time.time() - t0}
                self.stats["rpc_error"] += 1
                return {"kind": "rpc_error", "code": code,
                        "message": str(d["error"].get("message"))[:400], "dt": time.time() - t0}
            return {"kind": "ok", "result": d, "dt": time.time() - t0, "bytes": len(raw)}
        except urllib.error.HTTPError as e:
            self.stats["http"][e.code] = self.stats["http"].get(e.code, 0) + 1
            if e.code == 429:
                self.stats["http_429"] += 1
            return {"kind": "http", "status": e.code,
                    "retry_after": _retry_after(e.headers.get("Retry-After")) if e.headers else None,
                    "body": e.read()[:250].decode("utf-8", "replace"), "dt": time.time() - t0}
        except Exception as e:  # noqa: BLE001 — tout le reste est du transport, et se dit
            self.stats["transport"] += 1
            return {"kind": "transport", "error": repr(e)[:250], "dt": time.time() - t0}

    def _with_backoff(self, payload, timeout=None):
        """429 : ATTENTE (Retry-After, sinon exponentielle bornée), comptée. Transport / 502-504 : relances.

        Tout est compté dans `stats` (`http_429`, `attente_429_s`, `retries`) et remonte au battement.
        """
        delay = 0.4
        attente_429 = self.ATTENTE_429_INITIALE_S
        n_429 = 0
        attendu_429 = 0.0
        essais = 0
        while True:
            r = self._post(payload, timeout=timeout)
            if r["kind"] == "http" and r.get("status") == 429:
                n_429 += 1
                ra = r.get("retry_after")
                w = min(ra, self.ATTENTE_429_MAX_S) if ra is not None else min(attente_429,
                                                                                 self.ATTENTE_429_MAX_S)
                if n_429 > self.ESSAIS_429_MAX or attendu_429 + w > self.ATTENTE_429_TOTALE_MAX_S:
                    return r
                attente_429 *= 2
                attendu_429 += w
                self.stats["attente_429_s"] = round(self.stats["attente_429_s"] + w, 3)
                self.stats["retries"] += 1
                self._sleep(w)
                continue
            retryable = (r["kind"] == "transport") or (r["kind"] == "http" and r.get("status") in (502, 503, 504))
            if not retryable or essais >= self.max_retries:
                return r
            essais += 1
            self.stats["retries"] += 1
            self._sleep(delay + random.random() * 0.2)
            delay *= 2

    # ------------------------------------------------------------------ appels

    def call(self, method, params, timeout=None):
        if method in FORBIDDEN_METHODS:
            raise RpcRefused(
                f"REFUS DU CLIENT : « {method} » signe ou expose des clés. Le veilleur est en LECTURE SEULE "
                f"par construction : ce qui vérifie ne doit pas pouvoir signer.")
        if method not in READ_ONLY_METHODS:
            raise RpcRefused(
                f"REFUS DU CLIENT : « {method} » n'est pas dans la liste blanche de lecture seule. "
                f"L'ajouter est une décision explicite, pas un effet de bord.")
        r = self._with_backoff({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout)
        if r["kind"] != "ok":
            return r
        res = r["result"]
        if not isinstance(res, dict) or "result" not in res:
            self.stats["rpc_error"] += 1
            return {"kind": "rpc_error", "code": None, "message": f"réponse sans champ result : {str(res)[:200]}"}
        return {"kind": "ok", "result": res["result"], "dt": r["dt"], "bytes": r.get("bytes", 0)}

    def must(self, method, params, timeout=None):
        """Comme `call`, mais un échec est une EXCEPTION. À utiliser partout où un résultat manquant
        ne doit surtout pas se lire comme un résultat vide."""
        r = self.call(method, params, timeout=timeout)
        if r["kind"] != "ok":
            raise RpcUnavailable(f"{method} a échoué : {json.dumps(r, ensure_ascii=False)[:400]}")
        return r["result"]

    # ------------------------------------------------------------------ commodités

    def block_number(self):
        return int(self.must("eth_blockNumber", []), 16)

    def chain_id(self):
        return int(self.must("eth_chainId", []), 16)

    def block(self, tag):
        b = tag if isinstance(tag, str) else hex(tag)
        r = self.must("eth_getBlockByNumber", [b, False])
        if r is None:
            raise RpcUnavailable(f"eth_getBlockByNumber({b}) a rendu null : le bloc n'existe pas encore ici.")
        return r

    def block_timestamp(self, tag):
        return int(self.block(tag)["timestamp"], 16)

    def code_at(self, address, tag="latest"):
        return self.must("eth_getCode", [address, tag if isinstance(tag, str) else hex(tag)])

    def eth_call(self, to, data, block="latest", timeout=None):
        b = block if isinstance(block, str) else hex(block)
        return self.call("eth_call", [{"to": to, "input": data}, b], timeout=timeout)

    def get_logs(self, address, topics, from_block, to_block, timeout=None):
        params = {"address": address, "fromBlock": hex(from_block), "toBlock": hex(to_block)}
        if topics:
            params["topics"] = topics
        return self.call("eth_getLogs", [params], timeout=timeout)

    # ------------------------------------------------------------------ journaux par tranches

    def get_logs_chunked(self, address, topics, from_block, to_block, max_span=1000, timeout=None):
        """Ramène TOUS les journaux de la plage, par tranches.

        Mesure de l'atelier 0 : une plage ≤ ~1 000 blocs n'a aucune limite de RÉSULTATS ; au-delà, le nœud
        refuse à 10 000 journaux avec un message qui ment sur sa nature (« limit of 10000 » est en réalité
        une limite de PLAGE). On reste donc sous la plage sûre et on réduit encore en cas de refus.

        Assertion de COUVERTURE (KE#111) : la réunion des tranches doit recouvrir EXACTEMENT
        [from_block, to_block]. Une tranche perdue ne doit pas produire une liste plausible.
        """
        if to_block < from_block:
            raise ValueError("plage vide : to_block < from_block")
        out = []
        covered = []
        cur = from_block
        span = max_span
        while cur <= to_block:
            hi = min(cur + span - 1, to_block)
            r = self.get_logs(address, topics, cur, hi, timeout=timeout)
            if r["kind"] != "ok":
                # On ne découpe QUE sur une erreur de taille de plage explicitement reconnue. Un 429 (déjà
                # attendu par `_with_backoff`), un transport, une autre erreur : échec BRUYANT, sans
                # multiplier les appels.
                if est_erreur_de_plage(r) and span > 16:
                    span = max(16, span // 4)
                    self.stats["plages_découpées"] += 1
                    continue
                raise RpcUnavailable(
                    f"eth_getLogs [{cur},{hi}] a échoué ({'plage déjà réduite à ' + str(span) + ' blocs' if est_erreur_de_plage(r) else 'erreur non liée à la taille de plage : pas de découpage'}) : "
                    f"{json.dumps(r, ensure_ascii=False)[:300]}")
            out.extend(r["result"])
            covered.append((cur, hi))
            cur = hi + 1
        total = sum(b - a + 1 for a, b in covered)
        want = to_block - from_block + 1
        if total != want:
            raise RpcUnavailable(
                f"COUVERTURE INCOMPLÈTE : {total} blocs couverts pour {want} demandés. "
                f"Un trou de journaux rend tout contrôle en aval faux — on s'arrête ici.")
        # les tranches doivent être contiguës et ordonnées, sinon la somme ci-dessus peut mentir
        for i in range(1, len(covered)):
            if covered[i][0] != covered[i - 1][1] + 1:
                raise RpcUnavailable("COUVERTURE NON CONTIGUË : tranches disjointes, contrôle abandonné.")
        return out, covered
