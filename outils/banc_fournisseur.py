"""Banc du PROFIL de fournisseur : un faux dRPC local, et le client du paquet scellé construit depuis le `.env`
que `preparer.py` a réellement écrit.

Le faux fournisseur refuse comme dRPC, mesuré le 2026-09-24 (rapport veilleur §13.2) : toute plage
`eth_getLogs` de plus de 101 blocs (`toBlock - fromBlock > 100`) est rejetée en **HTTP 400**, corps
`{"error":{"message":"ranges over 10000 blocks are not supported on free plan","code":35}}` — le message ment
sur le chiffre, exactement comme l'original. Il écoute sur 127.0.0.1, dans la plage réservée 18570-18579.

Trois mesures, et c'est leur CONJONCTION qui prouve quelque chose (KE#121) :
  1. fidélité du faux : 101 blocs acceptés, 102 refusés — sinon un « zéro refus » plus bas serait vide ;
  2. `.env` AVEC le profil (celui que `preparer.py` écrit) : 1 000 blocs lus en ZÉRO refus, aucune tranche
     au-delà de 101 blocs ;
  3. témoin négatif : le MÊME `.env` sans la ligne de profil se fait refuser au moins une fois — c'est la
     situation que la configuration doit empêcher.

    python3 -B outils/banc_fournisseur.py --env <veilleur-b.env écrit par preparer.py> [--port 18570]
Sortie 0 si les trois tiennent, 1 sinon (le motif est imprimé).
"""
import argparse
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ICI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = range(18570, 18580)
SPAN_ACCEPTE = 101
REFUS = {"jsonrpc": "2.0", "id": None,
         "error": {"message": "ranges over 10000 blocks are not supported on free plan", "code": 35}}


class FauxDrpc(BaseHTTPRequestHandler):
    journal = []          # (from, to, accepté)

    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)))
        lot = req if isinstance(req, list) else [req]
        out, statut = [], 200
        for r in lot:
            if r.get("method") != "eth_getLogs":
                out.append({"jsonrpc": "2.0", "id": r.get("id"), "error": {"code": -32601, "message": "banc"}})
                continue
            f = r["params"][0]
            a, b = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            ok = (b - a) <= SPAN_ACCEPTE - 1
            FauxDrpc.journal.append((a, b, ok))
            if ok:
                out.append({"jsonrpc": "2.0", "id": r.get("id"), "result": []})
            else:
                statut = 400
                out.append(dict(REFUS, id=r.get("id")))
        corps = json.dumps(out if isinstance(req, list) else out[0]).encode()
        self.send_response(statut)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)


def demarrer(port=None):
    for p in ([port] if port else PORTS):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), FauxDrpc)
        except OSError:
            continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, p
    raise SystemExit("ARRÊT : aucun port libre dans 18570-18579.")


def client_depuis_env(chemin_env, url):
    if ICI not in sys.path:
        sys.path.insert(0, ICI)
    from veilleur.config import Settings, load_env
    from veilleur.rpc import client_depuis
    env = load_env(chemin_env, required=Settings.REQUIRED)
    # le faux dRPC sert le rôle JOURNAUX (et, s'il y a deux rôles, l'état aussi : rien ne doit sortir d'ici)
    if env.get("SPINDEX_RPC_URL_JOURNAUX"):
        env["SPINDEX_RPC_URL_JOURNAUX"] = url
        env["SPINDEX_RPC_URL_ETAT"] = url
    else:
        env["SPINDEX_RPC_URL"] = url
    return client_depuis(Settings(env))


def lire(client, n_blocs=1000):
    FauxDrpc.journal.clear()
    client._sleep = lambda s: None
    client.get_logs_chunked("0x" + "11" * 20, [], 10_000, 10_000 + n_blocs - 1)
    refus = sum(1 for _, _, ok in FauxDrpc.journal if not ok)
    plus_large = max(b - a + 1 for a, b, _ in FauxDrpc.journal)
    return refus, len(FauxDrpc.journal), plus_large


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", required=True)
    ap.add_argument("--port", type=int)
    a = ap.parse_args(argv)
    srv, port = demarrer(a.port)
    url = f"http://127.0.0.1:{port}/"
    motifs = []
    try:
        # 1. fidélité du faux : il accepte 101 et refuse 102 (sinon « zéro refus » ne dirait rien)
        c = client_depuis_env(a.env, url)
        c.max_log_span = 1_000_000
        for n, attendu in ((101, True), (102, False)):
            FauxDrpc.journal.clear()
            try:
                c.get_logs(("0x" + "11" * 20), [], 5_000, 5_000 + n - 1)
            except Exception:
                pass
            vu = FauxDrpc.journal[0][2] if FauxDrpc.journal else None
            if vu is not attendu:
                motifs.append(f"faux_infidele: plage de {n} blocs {'acceptée' if vu else 'refusée'}")

        # 2. le .env tel qu'écrit par preparer.py
        with open(a.env, encoding="utf-8") as fh:
            lignes = fh.read().splitlines()
        if not any(l.startswith(("SPINDEX_RPC_PROFIL=", "SPINDEX_RPC_PROFIL_JOURNAUX=")) for l in lignes):
            motifs.append("profil_absent: le .env écrit par preparer.py ne porte pas de profil pour les journaux")
        r_avec = lire(client_depuis_env(a.env, url))
        if r_avec[0] != 0 or r_avec[2] > SPAN_ACCEPTE:
            motifs.append(f"profil_non_portant: {r_avec[0]} refus sur {r_avec[1]} requêtes, "
                          f"tranche max {r_avec[2]} blocs")

        # 3. témoin négatif : le même .env SANS la ligne de profil se fait refuser
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False, encoding="utf-8") as t:
            # « sans profil » : un seul fournisseur, sans profil (une déclaration par rôle ne peut pas omettre
            # le sien — elle serait refusée à la configuration, ce qui ne mesurerait rien ici)
            sans = [l for l in lignes if not l.startswith(("SPINDEX_RPC_PROFIL", "SPINDEX_RPC_URL_"))]
            sans.append(f"SPINDEX_RPC_URL='{url}'")
            t.write("\n".join(sans) + "\n")
        os.chmod(t.name, 0o600)
        try:
            r_sans = lire(client_depuis_env(t.name, url))
        finally:
            os.remove(t.name)
        if r_sans[0] == 0:
            motifs.append("temoin_negatif_muet: sans profil, aucun refus — le faux ne mesure rien")
    finally:
        srv.shutdown()

    if motifs:
        print("PROFIL NON PROUVÉ :\n  " + "\n  ".join(motifs))
        return 1
    print(f"PROFIL PORTANT : avec profil {r_avec[0]} refus / {r_avec[1]} requêtes (tranche max {r_avec[2]}) ; "
          f"sans profil {r_sans[0]} refus / {r_sans[1]} requêtes ; faux fidèle (101 accepté, 102 refusé)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
