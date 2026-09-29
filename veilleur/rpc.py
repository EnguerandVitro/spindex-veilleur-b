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

Et une troisième forme, mesurée le 2026-09-24 sur dRPC : une erreur **applicative** JSON-RPC servie
dans un corps **HTTP 400**. Tant que le transport avalait ces corps, l'erreur n'atteignait jamais le
classificateur : elle ressortait en `kind: http`, c'est-à-dire « le réseau a mal répondu », alors
que le nœud avait parfaitement compris la question et refusé de répondre. Le statut est CONSERVÉ
(`http_status`) — on ne le perd pas, on cesse simplement de s'arrêter à lui.

Rien de ce qui est SPÉCIFIQUE à un fournisseur ne vit ici : les signatures de refus et les profils
mesurés sont dans `fournisseurs.py`, et la taille de plage comme l'en-tête viennent de `.env`.
"""
import json
import random
import time
import urllib.error
import urllib.request

from .fournisseurs import (CLASSES_DECOUPABLES, CLASSES_TRANSITOIRES, MOTIF_USER_AGENT_REFUSE, SPAN_LOGS_DEFAUT,
                           SPAN_LOGS_PLANCHER, USER_AGENT_DEFAUT, classer, explique)

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


# Découper une plage de journaux est autorisé par DEUX classes de refus seulement, et ces classes
# sont établies par des messages MESURÉS (`fournisseurs.SIGNATURES`), plus par une expression
# régulière écrite de mémoire. Un 429 n'est pas une plage trop large : découper sur un 429 multiplie
# les appels au moment précis où le nœud demande d'en faire moins (mesuré le 2026-09-21 : 16 tranches
# sur 40 en échec sur un contrat actif, avec l'ancien code qui divisait la plage par 4).
def est_erreur_de_plage(r):
    """Vrai UNIQUEMENT si le refus appartient à une classe mesurée qui autorise le découpage."""
    return classer(r)[0] in CLASSES_DECOUPABLES


def _erreur_jsonrpc(corps):
    """Rend le dict `error` si `corps` est une réponse JSON-RPC en erreur, sinon None. Jamais
    d'exception : un corps HTML de frontal doit rester un refus de transport, pas un plantage."""
    try:
        d = json.loads(corps)
    except (ValueError, TypeError):
        return None
    if isinstance(d, dict) and isinstance(d.get("error"), dict):
        return d["error"]
    return None


def _retry_after(v):
    """`Retry-After` en secondes (entier ou décimal) ; une date HTTP n'est pas interprétée (None)."""
    try:
        x = float(str(v).strip())
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


class RpcRefused(RuntimeError):
    """Le client a refusé d'émettre : méthode hors lecture seule."""


# Délai minimal de CHAQUE opération socket d'un appel émis sous échéance dure (`_borne` : ce n'est pas un plafond de
# durée totale, `urllib` n'en connaît pas).
PLANCHER_DELAI_APPEL_S = 1.0


class EcheanceDepassee(RuntimeError):
    """L'échéance DURE d'une lecture par tranches est passée : la lecture est ABANDONNÉE entre deux tranches, et
    l'appelant n'en tire aucune conclusion (le segment en vol n'est pas inscrit). Pas une panne du fournisseur."""


class RpcUnavailable(RuntimeError):
    """Le RPC n'a pas répondu utilement. JAMAIS à confondre avec « rien à signaler »."""


def verifier_user_agent(ua):
    """L'en-tête est CONFIGURABLE mais pas libre : `Python-urllib/*` — celui que `urllib` pose tout
    seul quand on n'en met aucun — est refusé en 403 par les TROIS fournisseurs mesurés (Cloudflare,
    « error code: 1010 »). Le laisser passer produirait une panne de lecture totale dont le motif
    n'apparaîtrait nulle part."""
    if not ua or not str(ua).strip():
        raise RpcRefused(
            "ARRÊT : user-agent vide. Sans en-tête explicite, `urllib` pose « Python-urllib/… », "
            "que les trois fournisseurs mesurés refusent en 403 (Cloudflare 1010).")
    if MOTIF_USER_AGENT_REFUSE.match(str(ua)):
        raise RpcRefused(
            f"ARRÊT : user-agent « {ua} » — MESURÉ refusé en 403 par les trois fournisseurs "
            f"(Cloudflare « error code: 1010 »). Posez SPINDEX_RPC_USER_AGENT à autre chose.")
    return str(ua)


def verifier_span(n):
    n = int(n)
    if n < SPAN_LOGS_PLANCHER:
        raise RpcRefused(
            f"ARRÊT : taille de plage de journaux {n} < plancher {SPAN_LOGS_PLANCHER}. Sous ce "
            f"plancher, le découpage ne converge plus : c'est un fournisseur à mesurer, pas une "
            f"valeur à baisser.")
    return n


RELANCE_ESSAIS_MAX = 10          # au-delà, ce n'est plus une relance, c'est une attente déguisée
RELANCE_ATTENTE_MAX_S = 120.0   # une attente unique plus longue masquerait une panne durable


def _entier_strict(v, nom):
    if isinstance(v, bool) or isinstance(v, float) or (isinstance(v, str) and not v.strip().isdigit()):
        raise RpcRefused(f"ARRÊT : relance transitoire — `{nom}` doit être un ENTIER ({v!r}).")
    return int(v)


def verifier_relance(relance):
    """`relance_transitoire` : None (aucune relance déclarée) ou les TROIS clés, dans leurs plafonds.

    Rien d'implicite (KE#105), et rien de démesuré : au plus RELANCE_ESSAIS_MAX relances, au plus
    RELANCE_ATTENTE_MAX_S par attente. Une déclaration hors plafond est refusée, pas tronquée."""
    if relance is None:
        return None
    try:
        r = {"essais": _entier_strict(relance["essais"], "essais"),
             "attente_initiale_s": float(relance["attente_initiale_s"]),
             "attente_max_s": float(relance["attente_max_s"])}
    except (KeyError, TypeError, ValueError) as e:
        raise RpcRefused(f"ARRÊT : relance transitoire incomplète ou illisible ({e!r}) : il faut `essais`, "
                         f"`attente_initiale_s` et `attente_max_s`, toutes les trois.") from e
    if r["essais"] < 1 or r["attente_initiale_s"] <= 0 or r["attente_max_s"] < r["attente_initiale_s"]:
        raise RpcRefused(f"ARRÊT : relance transitoire incohérente {r} (essais ≥ 1, 0 < initiale ≤ max).")
    if r["essais"] > RELANCE_ESSAIS_MAX or r["attente_max_s"] > RELANCE_ATTENTE_MAX_S:
        raise RpcRefused(f"ARRÊT : relance transitoire hors plafond {r} (essais ≤ {RELANCE_ESSAIS_MAX}, "
                         f"attente_max_s ≤ {RELANCE_ATTENTE_MAX_S:g}).")
    return r


def client_depuis(settings):
    """Construit le client AVEC les réglages du fournisseur configuré. Point unique : un appelant qui
    ferait `RpcClient(s.rpc_url)` tout seul retomberait sur les défauts du paquet, c'est-à-dire sur
    les hypothèses d'un AUTRE fournisseur que celui qui est en face."""
    roles = getattr(settings, "rpc_roles", None)
    if roles:
        return ClientParRole(roles["journaux"], roles["etat"],
                             user_agent=getattr(settings, "rpc_user_agent", USER_AGENT_DEFAUT))
    return RpcClient(
        settings.rpc_url,
        user_agent=getattr(settings, "rpc_user_agent", USER_AGENT_DEFAUT),
        max_log_span=getattr(settings, "rpc_max_log_span", SPAN_LOGS_DEFAUT),
        relance_transitoire=getattr(settings, "rpc_relance_transitoire", None))


class RpcClient:
    # Sur 429 : attente, JAMAIS de découpage. `Retry-After` respecté s'il est présent (plafonné), sinon repli
    # exponentiel borné. Le total d'attente par appel est borné aussi : au-delà, l'appel ÉCHOUE bruyamment.
    ATTENTE_429_INITIALE_S = 0.5
    ATTENTE_429_MAX_S = 30.0
    ESSAIS_429_MAX = 8
    ATTENTE_429_TOTALE_MAX_S = 120.0

    # Un découpage de plage divise par 4 : depuis 1 000 blocs, trois découpages suffisent à atteindre
    # le plancher. Au-delà, ce n'est plus un ajustement, c'est une boucle — et elle s'arrête ici,
    # bruyamment, en nommant la valeur à poser dans `.env`.
    DECOUPAGES_MAX = 6

    def __init__(self, url, timeout=120, max_retries=4, user_agent=USER_AGENT_DEFAUT,
                 max_log_span=SPAN_LOGS_DEFAUT, relance_transitoire=None):
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.ua = verifier_user_agent(user_agent)
        self.max_log_span = verifier_span(max_log_span)
        # Relance des refus TRANSITOIRES (`CLASSES_TRANSITOIRES`) : déclarée par le profil, sans défaut.
        self.relance_transitoire = verifier_relance(relance_transitoire)
        self._sleep = time.sleep
        # Échéance DURE (temps réel) posée par un appelant à durée bornée (différentiel segmenté) : chaque appel
        # a un délai ≤ ce qui reste, et aucune relance ni attente ne la franchit (revue 2026-09-29, P1-B).
        # None (la passe, tout le reste) : comportement inchangé.
        self._echeance_dure = None
        self.stats = {"calls": 0, "http": {}, "transport": 0, "rpc_error": 0, "http_429": 0, "retries": 0,
                      "attente_429_s": 0.0, "plages_découpées": 0,
                      "relances_transitoires": 0, "attente_transitoire_s": 0.0,
                      # Dernière taille de tranche réellement utilisée : c'est elle qui dit à
                      # l'exploitant quoi poser dans SPINDEX_RPC_MAX_LOG_SPAN pour cesser de payer
                      # trois appels de découverte à chaque passe.
                      "span_logs": int(max_log_span)}

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
            corps = e.read()[:400].decode("utf-8", "replace")
            # ORDRE VOULU (KE#138) : le plus spécifique d'abord, le fourre-tout EN DERNIER.
            # 1. limitation de débit : elle se traite par l'ATTENTE, quel que soit le corps.
            if e.code == 429:
                self.stats["http_429"] += 1
                return {"kind": "http", "status": 429,
                        "retry_after": _retry_after(e.headers.get("Retry-After")) if e.headers else None,
                        "body": corps[:250], "dt": time.time() - t0}
            # 2. erreur APPLICATIVE JSON-RPC servie dans un corps 4xx (mesuré sur dRPC le 2026-09-24 :
            #    HTTP 400 + {"error":{"message":"ranges over 10000 blocks…","code":35}}). Le nœud a
            #    compris la question et l'a refusée : c'est une `rpc_error`, pas une panne de
            #    transport. Le statut est conservé, il n'est simplement plus terminal.
            err = _erreur_jsonrpc(corps)
            if err is not None:
                self.stats["rpc_error"] += 1
                return {"kind": "rpc_error", "code": err.get("code"),
                        "message": str(err.get("message"))[:400], "http_status": e.code,
                        "dt": time.time() - t0}
            # 3. fourre-tout : un refus HTTP sans corps exploitable.
            return {"kind": "http", "status": e.code,
                    "retry_after": _retry_after(e.headers.get("Retry-After")) if e.headers else None,
                    "body": corps[:250], "dt": time.time() - t0}
        except Exception as e:  # noqa: BLE001 — tout le reste est du transport, et se dit
            self.stats["transport"] += 1
            return {"kind": "transport", "error": repr(e)[:250], "dt": time.time() - t0}

    def poser_echeance_dure(self, t):
        """Pose (ou retire, None) l'échéance dure de CE client et de son client d'état s'il en a un."""
        self._echeance_dure = t
        autre = getattr(self, "etat", None)
        if autre is not None and autre is not self:
            autre._echeance_dure = t

    def _borne(self, timeout, attente=0.0):
        """Délai du prochain appel sous l'échéance dure ; lève `EcheanceDepassee` si elle est (ou serait) franchie.

        Ce que ce délai GARANTIT, et ce qu'il ne garantit pas. `urllib` applique `timeout` à CHAQUE opération de
        socket (connexion, chaque lecture), pas à la durée totale de l'appel : une réponse livrée goutte à goutte, ou
        une résolution DNS lente, peut dépasser l'échéance dure de plus que `PLANCHER_DELAI_APPEL_S`. Garanti : aucun
        appel n'est ÉMIS et aucune attente de relance n'est COMMENCÉE au-delà de l'échéance dure (refus avant de
        dormir) ; chaque opération socket d'un appel émis attend au plus max(1 s, ce qui reste). Le dépassement
        total n'est borné que par la MARGE du job : pour `b`, échéance dure 1 740 + 120 = 1 860 s, kill à 2 160 s,
        300 s réservées au jugement, au lot et à sa revérification (`outils/preparer.py`)."""
        e = self._echeance_dure
        if e is None:
            return timeout
        reste = e - time.time() - attente
        if reste <= 0:
            raise EcheanceDepassee(f"échéance dure atteinte ({round(-reste, 1)} s au-delà) : appel non émis")
        return max(PLANCHER_DELAI_APPEL_S, min(timeout or self.timeout, reste))

    def _with_backoff(self, payload, timeout=None):
        """429 : ATTENTE (Retry-After, sinon exponentielle bornée), comptée. Transport / 502-504 : relances.

        Tout est compté dans `stats` (`http_429`, `attente_429_s`, `retries`) et remonte au battement.
        """
        delay = 0.4
        attente_429 = self.ATTENTE_429_INITIALE_S
        n_429 = 0
        attendu_429 = 0.0
        essais = 0
        essais_t = 0          # relances de refus TRANSITOIRES, bornées par le profil
        attendu_t = 0.0
        while True:
            r = self._post(payload, timeout=self._borne(timeout))
            if r["kind"] == "http" and r.get("status") == 429:
                n_429 += 1
                ra = r.get("retry_after")
                w = min(ra, self.ATTENTE_429_MAX_S) if ra is not None else min(attente_429,
                                                                                 self.ATTENTE_429_MAX_S)
                if n_429 > self.ESSAIS_429_MAX or attendu_429 + w > self.ATTENTE_429_TOTALE_MAX_S:
                    return r
                attente_429 *= 2
                attendu_429 += w
                self._borne(timeout, attente=w)          # aucune attente ne franchit l'échéance dure
                self.stats["attente_429_s"] = round(self.stats["attente_429_s"] + w, 3)
                self.stats["retries"] += 1
                self._sleep(w)
                continue
            # Refus TRANSITOIRE du fournisseur (ex. dRPC 408 « Request timeout ») : relance BORNÉE à attente
            # croissante, paramétrée par le profil. Sans paramètres déclarés : on ne relance PAS, on rend
            # le refus annoté — l'appelant l'arrête en nommant la clé à déclarer (KE#105). Au-delà des
            # essais : rendu annoté aussi, jamais avalé (KE#131 : borne, puis échec bruyant).
            if r["kind"] == "rpc_error" and classer(r)[0] in CLASSES_TRANSITOIRES:
                rel = self.relance_transitoire
                if rel is None:
                    return dict(r, transitoire={"relances": 0, "non_déclarée": True})
                if essais_t >= rel["essais"]:
                    return dict(r, transitoire={"relances": essais_t, "épuisée": True,
                                                "attente_s": round(attendu_t, 3)})
                w = min(rel["attente_initiale_s"] * (2 ** essais_t), rel["attente_max_s"])
                self._borne(timeout, attente=w)
                essais_t += 1
                attendu_t += w
                self.stats["relances_transitoires"] += 1
                self.stats["attente_transitoire_s"] = round(self.stats["attente_transitoire_s"] + w, 3)
                self._sleep(w)
                continue
            retryable = (r["kind"] == "transport") or (r["kind"] == "http" and r.get("status") in (502, 503, 504))
            if not retryable or essais >= self.max_retries:
                return r
            essais += 1
            self._borne(timeout, attente=delay)
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

    def get_logs_chunked(self, address, topics, from_block, to_block, max_span=None, timeout=None,
                         sans_adresse=False):
        """Ramène TOUS les journaux de la plage, par tranches.

        La taille de tranche vient de la CONFIGURATION (`SPINDEX_RPC_MAX_LOG_SPAN`), pas d'une
        constante du code : elle est spécifique au fournisseur. Mesures du 2026-09-24 sur la 46630 —
        nœud officiel : aucune limite de plage, mais 10 000 journaux maximum ; publicnode : 50 000
        blocs ; dRPC : **101 blocs**, avec un message qui annonce 10 000 et ment.

        En cas de refus, le découpage n'est autorisé QUE par une classe de refus mesurée
        (`fournisseurs.CLASSES_DECOUPABLES`). Un refus inconnu est un ARRÊT qui nomme le remède :
        deviner « c'est sûrement une plage trop large » ferait redécouper en boucle sur une panne
        qui n'a rien à voir.

        Assertion de COUVERTURE (KE#111) : la réunion des tranches doit recouvrir EXACTEMENT
        [from_block, to_block]. Une tranche perdue ne doit pas produire une liste plausible.
        """
        if to_block < from_block:
            raise ValueError("plage vide : to_block < from_block")
        if not address and not sans_adresse:
            # Hypothèse de fournisseur, mesurée le 2026-09-24 : publicnode REFUSE toute requête de
            # journaux sans filtre d'adresse (« Please specify an address in your request … »), à
            # 100 blocs comme à 10 000. Aucun découpage ne répare ça. Un appelant qui veut vraiment
            # lire sans filtre le DIT (`sans_adresse=True`) et sait que ça ne marche pas partout.
            raise RpcRefused(
                "REFUS DU CLIENT : lecture de journaux SANS filtre d'adresse. Au moins un des "
                "fournisseurs mesurés la refuse quelle que soit la plage, et un contrôle ne doit pas "
                "dépendre d'un nœud en particulier. Passez `sans_adresse=True` si c'est voulu.")
        out = []
        covered = []
        cur = from_block
        span = verifier_span(max_span if max_span is not None else self.max_log_span)
        decoupages = 0
        while cur <= to_block:
            # (l'échéance DURE d'un appelant borné est portée par le CLIENT, `_borne` : chaque appel, relances
            # comprises — un contrôle ici entre deux tranches serait une garde doublée, indémontrable, KE#139)
            hi = min(cur + span - 1, to_block)
            r = self.get_logs(address, topics, cur, hi, timeout=timeout)
            if r["kind"] != "ok":
                # Un 429 est déjà attendu par `_with_backoff` ; s'il ressort ici c'est qu'il persiste.
                if est_erreur_de_plage(r) and span > SPAN_LOGS_PLANCHER:
                    decoupages += 1
                    if decoupages > self.DECOUPAGES_MAX:
                        raise RpcUnavailable(
                            f"eth_getLogs [{cur},{hi}] : {decoupages} découpages sur un seul appel, "
                            f"au-delà de {self.DECOUPAGES_MAX}. Ce n'est plus un ajustement, c'est une "
                            f"boucle : posez SPINDEX_RPC_MAX_LOG_SPAN à la taille mesurée de ce "
                            f"fournisseur. Dernier refus : {json.dumps(r, ensure_ascii=False)[:300]}")
                    span = max(SPAN_LOGS_PLANCHER, span // 4)
                    self.stats["plages_découpées"] += 1
                    self.stats["span_logs"] = span
                    continue
                if est_erreur_de_plage(r):
                    pourquoi = (f"plage déjà réduite au plancher de {span} blocs, et ce fournisseur "
                                f"la refuse encore")
                elif r["kind"] == "transport":
                    # Le réseau, pas le nœud : parler ici de « signature inconnue » enverrait
                    # l'exploitant mesurer un fournisseur qui n'a jamais répondu.
                    pourquoi = "panne de TRANSPORT (le nœud n'a pas répondu), rien à classer"
                elif r["kind"] == "http" and r.get("status") == 429:
                    # Arbitrage Q4 : sur un 429 on ATTEND (`_with_backoff`), on ne découpe JAMAIS.
                    # S'il ressort jusqu'ici, c'est que l'attente bornée n'a pas suffi.
                    pourquoi = ("limitation de débit persistante — on ne découpe JAMAIS sur un 429 : "
                                "cela multiplierait les appels au moment précis où le nœud en demande "
                                "moins")
                elif r.get("transitoire", {}).get("non_déclarée"):
                    pourquoi = ("refus TRANSITOIRE du fournisseur (classe delai_fournisseur) et AUCUNE relance "
                                "déclarée pour ce profil : déclarer `relance_transitoire` dans "
                                "veilleur/fournisseurs.py:PROFILS, ou poser SPINDEX_RPC_RELANCE_ESSAIS, "
                                "SPINDEX_RPC_RELANCE_ATTENTE_INITIALE_S et SPINDEX_RPC_RELANCE_ATTENTE_MAX_S")
                elif r.get("transitoire", {}).get("épuisée"):
                    t = r["transitoire"]
                    pourquoi = (f"délai du fournisseur PERSISTANT : {t['relances']} relances ({t['relances'] + 1} "
                                f"appels), {t['attente_s']} s d'attente, aucune réponse — refus transitoire devenu "
                                f"durable ; on ne découpe pas (la plage n'est pas en cause)")
                else:
                    pourquoi = explique(r)
                raise RpcUnavailable(
                    f"eth_getLogs [{cur},{hi}] a échoué ({pourquoi}) : "
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


# Méthodes servies par le fournisseur des JOURNAUX quand les rôles sont séparés : ce qui permet de
# reconstruire événements et racines indépendamment. TOUT le reste (état à un bloc, têtes, blocs,
# code) va au fournisseur de l'ÉTAT — y compris la tête épinglée, pour que l'état soit lu à un bloc
# que CE fournisseur possède.
METHODES_JOURNAUX = frozenset({"eth_getLogs", "eth_getTransactionReceipt"})


class ClientParRole(RpcClient):
    """Deux fournisseurs, un par rôle. Le client lui-même EST celui des journaux (tranches, relances,
    découpage selon SON profil) ; l'état passe par `self.etat`. Les compteurs sont PARTAGÉS : le
    battement compte tous les appels, quel que soit le fournisseur.

    `eth_chainId` est demandé aux DEUX : deux fournisseurs qui ne parlent pas de la même chaîne ne
    forment pas un veilleur, ils en forment deux qui s'ignorent."""

    def __init__(self, journaux, etat, user_agent=USER_AGENT_DEFAUT):
        super().__init__(journaux["url"], user_agent=user_agent, max_log_span=journaux["span"],
                         relance_transitoire=journaux["relance"])
        self.etat = RpcClient(etat["url"], user_agent=user_agent, max_log_span=etat["span"],
                              relance_transitoire=etat["relance"])
        self.etat.stats = self.stats
        self.stats["appels_journaux"] = 0
        self.stats["appels_etat"] = 0

    def chain_ids(self):
        """`eth_chainId` de CHAQUE rôle, séparément — pour que la garde de chaîne nomme le rôle fautif."""
        self.stats["appels_journaux"] += 1
        self.stats["appels_etat"] += 1
        return {"journaux": int(self._must_role(super().call, "eth_chainId"), 16),
                "etat": int(self._must_role(self.etat.call, "eth_chainId"), 16)}

    def must_journaux(self, method, params):
        """Lecture EXPLICITE chez le fournisseur des JOURNAUX (hors routage) : sa tête, pour prouver qu'il
        a bien atteint la plage qu'on fige. Une exception si elle échoue, jamais un résultat vide."""
        self.stats["appels_journaux"] += 1
        return self._must_role(lambda m, p: RpcClient.call(self, m, p), method, params)

    @staticmethod
    def _must_role(appel, methode, params=None):
        r = appel(methode, params or [])
        if r["kind"] != "ok":
            raise RpcUnavailable(f"{methode} a échoué : {json.dumps(r, ensure_ascii=False)[:400]}")
        return r["result"]

    def call(self, method, params, timeout=None):
        if method in METHODES_JOURNAUX:
            self.stats["appels_journaux"] += 1
            return super().call(method, params, timeout=timeout)
        if method == "eth_chainId":
            self.stats["appels_journaux"] += 1
            self.stats["appels_etat"] += 1
            a = super().call(method, params, timeout=timeout)
            b = self.etat.call(method, params, timeout=timeout)
            if a["kind"] != "ok":
                return a
            if b["kind"] != "ok":
                return b
            if str(a["result"]).lower() != str(b["result"]).lower():
                return {"kind": "rpc_error", "code": None,
                        "message": f"les deux fournisseurs annoncent des chaînes DIFFÉRENTES (journaux "
                                   f"{a['result']}, état {b['result']}) : aucune lecture croisée possible"}
            return a
        self.stats["appels_etat"] += 1
        return self.etat.call(method, params, timeout=timeout)
