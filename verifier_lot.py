"""Vérifier un lot publié par l'instance `b` — à exécuter **du côté qui le lit**, pas du côté qui l'écrit.

C'est le pendant de `publier.py`, et c'est lui qui compte : un lot signé par celui qui le fabrique ne
prouve rien tant que personne ne vérifie. La machine de surveillance lance cette commande après avoir
tiré la branche `attestations`, et elle refuse le lot plutôt que de l'ingérer à moitié.

**L'ancre de confiance est HORS du lot** (KE#130). Sans `--clé-publique`, cette commande REFUSE : elle
ne se rabat jamais sur la clé que le lot transporte. Vérifier une signature contre la clé que le
document porte, c'est authentifier n'importe qui — c'est le défaut que la famille `veilleur` a corrigé
dans `verdict.verify_envelope` le 2026-09-23, et qu'on ne va pas réintroduire ici.

**Ce fichier est AUTONOME, et il doit le rester.** Il voyage seul à la racine de la branche
`attestations`, où il n'y a pas de paquet `veilleur` à importer : la machine de surveillance tire la
branche et lance ce fichier, point. Sa seule dépendance est `cryptography`. Il réimplémente donc deux
choses du paquet scellé — la sérialisation canonique et la vérification Ed25519 — et **une
réimplémentation se prouve par un test différentiel** (KE#119) : `outils/publier.py` compare, à chaque
signature, les octets rendus par `_canonique` d'ici à ceux de `veilleur.verdict.canonical`, sur le
manifeste RÉEL, et refuse de signer en cas d'écart. L'invariant n'est pas « ça marche chez moi », c'est
« octet pour octet identique à la référence, sur le document qu'on signe vraiment ».

Ce qui est contrôlé, et pourquoi chaque contrôle est là :
  1. `SIGNATURE.json` porte le bon **domaine** — une signature valide dans un autre domaine (un feu
     vert, par exemple) ne vaut pas ici ;
  2. la clé du lot **est** l'ancre attendue — sinon ARRÊT nommé, distinct d'une signature fausse ;
  3. la signature du **manifeste canonique** tient ;
  4. **chaque** fichier annoncé est présent et son sha256 correspond ;
  5. **aucun intrus** : un fichier du lot absent du manifeste est un ARRÊT (il aurait été ingéré sans
     jamais avoir été signé) ;
  6. **cardinal non nul** (KE#111) : un manifeste qui n'épingle rien passerait « sans faute ».

Sortie : 0 si le lot est intègre et signé par l'ancre, 2 sinon. Le verdict du veilleur (`JUGEMENT.json`)
n'entre PAS dans ce code de sortie : « le lot est authentique » et « le veilleur a trouvé quelque
chose » sont deux questions, et les confondre ferait lire une panne de transport comme une alerte
métier — ou l'inverse.

    python3 -B outils/verifier_lot.py --lot <dossier> --clé-publique <hex|fichier>
"""
import argparse
import hashlib
import json
import os
import re
import sys

MANIFESTE = "MANIFESTE.json"
SIGNATURE = "SIGNATURE.json"
DOMAINE = b"spindex-veilleur-b-lot/1\n"


_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")


class LotError(RuntimeError):
    pass


def _canonique(doc):
    """Sérialisation canonique — la MÊME que `veilleur.verdict.canonical`, octet pour octet.

    Clés triées, séparateurs sans espace, UTF-8 non échappé. Réécrite ici pour que ce fichier voyage
    seul (voir l'en-tête) ; l'égalité avec la référence est vérifiée à chaque signature par
    `outils/publier.py`, sur le manifeste réel, et un écart empêche de signer (KE#119).
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verifier_ed25519(clé_publique_hex, message, signature):
    """Ed25519 nu. Une signature invalide rend False ; tout le reste lève."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(clé_publique_hex))
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def charger_ancre(chemin):
    """L'ancre de confiance : 64 hexa, ou le chemin d'un fichier qui les contient.

    Absente, cette commande REFUSE. Elle ne se rabat JAMAIS sur la clé que le lot transporte : ce
    serait authentifier n'importe qui (KE#130).
    """
    if not chemin:
        raise LotError(
            "ARRÊT : aucune clé publique de confiance. Une signature ne se vérifie pas contre la clé "
            "que le lot transporte — n'importe qui fabriquerait alors un lot « vert » valide. Fournir "
            "`--clé-publique <hex|fichier>` ou poser SPINDEX_B_ANCRE.")
    val = str(chemin).strip()
    if _HEX32.match(val):
        return val.lower()
    if not os.path.exists(val):
        raise LotError(f"ARRÊT : ancre de confiance introuvable ({val}). Elle doit exister HORS du lot : "
                       f"c'est tout ce qui distingue un lot de l'instance b d'un lot fabriqué.")
    with open(val, encoding="utf-8") as fh:
        txt = fh.read().strip()
    if txt.startswith("{"):
        d = json.loads(txt)
        txt = (d.get("clé_publique") or d.get("cle_publique") or d.get("public_key") or "").strip()
    txt = txt.removeprefix("0x")
    if not _HEX32.match(txt):
        raise LotError(f"ARRÊT : {val} ne contient pas une clé publique Ed25519 (32 octets hexadécimaux).")
    return txt.lower()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def verifier(lot_dir, ancre):
    attendue = charger_ancre(ancre)                 # ARRÊT bruyant si absente

    for nom in (MANIFESTE, SIGNATURE):
        if not os.path.exists(os.path.join(lot_dir, nom)):
            raise LotError(f"ARRÊT : {nom} absent de {lot_dir} : ce n'est pas un lot.")
    with open(os.path.join(lot_dir, MANIFESTE), encoding="utf-8") as fh:
        man = json.load(fh)
    with open(os.path.join(lot_dir, SIGNATURE), encoding="utf-8") as fh:
        sig = json.load(fh)

    if sig.get("alg") != "ed25519":
        raise LotError(f"ARRÊT : algorithme « {sig.get('alg')} » inattendu.")
    if sig.get("domaine") != DOMAINE.decode():
        raise LotError(
            f"ARRÊT : domaine de signature « {sig.get('domaine')} », attendu « {DOMAINE.decode().strip()} ». "
            f"Une signature valide dans un autre domaine (un feu vert, par exemple) ne vaut pas ici.")
    portee = (sig.get("clé_publique") or "").strip().lower().removeprefix("0x")
    if portee != attendue:
        raise LotError(
            f"ARRÊT : lot signé par « {portee[:16] or '(absente)'}… », l'ancre attend « {attendue[:16]}… ». "
            f"Ce lot n'est pas celui de l'instance b que vous surveillez.")

    payload = _canonique(man)
    if hashlib.sha256(payload).hexdigest() != sig.get("empreinte_manifeste_sha256"):
        raise LotError("ARRÊT : l'empreinte du manifeste ne correspond pas à celle que la signature "
                       "annonce : le manifeste a été réécrit après signature.")
    if not _verifier_ed25519(attendue, DOMAINE + payload, bytes.fromhex(sig["signature"])):
        raise LotError("ARRÊT : signature invalide.")

    fichiers = man.get("fichiers") or {}
    if not fichiers:                                   # KE#111
        raise LotError("ARRÊT : le manifeste n'épingle AUCUN fichier — il ne gèle rien.")
    bouges = []
    for rel, want in sorted(fichiers.items()):
        p = os.path.join(lot_dir, rel)
        if not os.path.exists(p):
            bouges.append((rel, want, "ABSENT"))
        else:
            got = sha256(p)
            if got != want:
                bouges.append((rel, want, got))
    if bouges:
        lignes = "\n".join(f"  {r}\n    signé {w}\n    lu    {g}" for r, w, g in bouges)
        raise LotError(f"ARRÊT : {len(bouges)} fichier(s) du lot ont bougé depuis la signature.\n{lignes}")

    presents = []
    for racine, _d, noms in os.walk(lot_dir):
        for n in noms:
            presents.append(os.path.relpath(os.path.join(racine, n), lot_dir))
    intrus = sorted(set(presents) - set(fichiers) - {MANIFESTE, SIGNATURE})
    if intrus:
        raise LotError(
            f"ARRÊT : {len(intrus)} fichier(s) présents dans le lot mais absents du manifeste : "
            f"{intrus[:5]}. Ils seraient ingérés sans avoir jamais été signés.")

    return {"fichiers": len(fichiers), "signé_par": attendue,
            "produit_le": man.get("produit_le"), "empreinte_sources": man.get("empreinte_sources"),
            "jugement": man.get("jugement"), "exécution": man.get("exécution")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lot", required=True)
    ap.add_argument("--clé-publique", dest="cle", default=os.environ.get("SPINDEX_B_ANCRE") or None,
                    help="clé publique ATTENDUE : 64 hexa, ou chemin d'un fichier d'ancrage. "
                         "Défaut : variable SPINDEX_B_ANCRE. Absente ⇒ REFUS.")
    a = ap.parse_args(argv)
    try:
        rep = verifier(a.lot, a.cle)
    except Exception as e:                                          # noqa: BLE001
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    j = rep.get("jugement") or {}
    print(f"\nLOT AUTHENTIQUE : {rep['fichiers']} fichier(s), signé par {rep['signé_par'][:16]}…, "
          f"produit le {rep['produit_le']}.", file=sys.stderr)
    print(f"Jugement PORTÉ par ce lot (à lire, il ne change pas ce code de sortie) : "
          f"{j.get('verdict')} {j.get('motifs') or ''}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
