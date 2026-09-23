"""D'où viennent les artefacts : l'arbre `contracts/` chez nous, un LOT PUBLIÉ chez un tiers.

Pourquoi ce module existe
--------------------------
Le veilleur ne doit pas être un point unique de défaillance. La réponse retenue n'est pas
d'assouplir la règle de quorum, c'est de rendre la vérification **reproductible par n'importe qui** :
elle ne porte que sur des données publiques — les journaux de la chaîne et la table publiée — donc un
tiers peut la rejouer, et une panne de NOTRE instance cesse d'être une panne de la GARANTIE.

Or, tel qu'il était écrit, le vérificateur exigeait l'arbre `contracts/` : l'ABI compilée, la source
pour en extraire les constantes, le fichier scellé pour les recouper. Un tiers ne les a pas. Ce
module résout donc les artefacts depuis **deux dispositions**, et le reste du code n'a pas à savoir
laquelle :

- **`contracts/`** — chez nous : `out/X.sol/X.json`, `src/X.sol`, `rewards/rewards_constants.json` ;
- **lot publié** — chez un tiers : `X.abi.json`, `X.sol`, `rewards_constants.json`, `MANIFESTE.json`.

Le lot n'est pas un raccourci : il porte les MÊMES contrôles. L'empreinte `sha256` de chaque fichier
est épinglée dans le manifeste et vérifiée au chargement, et le `keccak256` de la source est confronté
à celui que l'ABI déclare — exactement comme dans l'arbre complet. Un lot dont un fichier a bougé
**s'arrête**, il ne dégrade pas.
"""
import hashlib
import json
import os

MANIFESTE = "MANIFESTE.json"


class ArtefactError(RuntimeError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Artefacts:
    """Chemins résolus + provenance. `disposition` vaut 'contracts' ou 'lot publié'."""

    def __init__(self, racine, disposition, abi_path, source_path, constants_path,
                 declared_keccak=None, manifeste=None):
        self.racine = racine
        self.disposition = disposition
        self.abi_path = abi_path
        self.source_path = source_path
        self.constants_path = constants_path
        self.declared_keccak = declared_keccak
        self.manifeste = manifeste or {}

    def charger_abi(self):
        """Rend (liste ABI, keccak256 déclaré de la source)."""
        d = json.load(open(self.abi_path, encoding="utf-8"))
        if isinstance(d, list):                       # lot publié : l'ABI nue
            if self.declared_keccak is None:
                raise ArtefactError(
                    "ARRÊT : lot publié sans `source_keccak256` au manifeste. Sans lui, rien ne relie "
                    "l'ABI à la source, et le décodage pourrait porter sur une autre version.")
            return d, self.declared_keccak
        abi = d.get("abi")
        if not abi:
            raise ArtefactError(f"ARRÊT : pas d'ABI dans {self.abi_path}.")
        md = d["metadata"] if isinstance(d.get("metadata"), dict) else json.loads(d["rawMetadata"])
        nom = os.path.basename(self.source_path)
        return abi, md["sources"][f"src/{nom}"]["keccak256"]

    def to_dict(self):
        return {"disposition": self.disposition, "racine": self.racine,
                "manifeste": {k: v for k, v in self.manifeste.items() if k != "fichiers"}}


def _lot(racine, name):
    m_path = os.path.join(racine, MANIFESTE)
    man = json.load(open(m_path, encoding="utf-8"))
    fichiers = man.get("fichiers") or {}
    # Assertion de CARDINAL (KE#111) : un manifeste vide n'épingle rien et passerait « sans faute ».
    if not fichiers:
        raise ArtefactError(f"ARRÊT : {m_path} n'épingle AUCUN fichier — il ne gèle rien.")
    bougés = []
    for rel, want in fichiers.items():
        p = os.path.join(racine, rel)
        if not os.path.exists(p):
            bougés.append((rel, want, "ABSENT"))
        else:
            got = _sha256(p)
            if got != want:
                bougés.append((rel, want, got))
    if bougés:
        lignes = "\n".join(f"  {r}\n    attendu {w}\n    lu      {g}" for r, w, g in bougés)
        raise ArtefactError(
            f"ARRÊT : {len(bougés)} fichier(s) du lot publié ont bougé depuis sa fabrication.\n{lignes}")
    # et rien d'étranger dans le lot : un fichier non épinglé est une dérive silencieuse
    présents = {f for f in os.listdir(racine) if os.path.isfile(os.path.join(racine, f))}
    intrus = sorted(présents - set(fichiers) - {MANIFESTE})
    if intrus:
        raise ArtefactError(
            f"ARRÊT : {len(intrus)} fichier(s) non épinglés dans le lot : {intrus[:5]}. "
            f"Un lot qui contient autre chose que ce qu'il annonce n'est pas un lot.")
    return Artefacts(
        racine, "lot publié",
        os.path.join(racine, f"{name}.abi.json"),
        os.path.join(racine, f"{name}.sol"),
        os.path.join(racine, "rewards_constants.json"),
        declared_keccak=man.get("source_keccak256", {}).get(name),
        manifeste=man,
    )


def resoudre(racine, name="SpindexRewards"):
    """Résout la disposition depuis la racine donnée. Aucune supposition : on REGARDE."""
    if not racine or not os.path.isdir(racine):
        raise ArtefactError(f"ARRÊT : racine d'artefacts introuvable ({racine}).")
    if os.path.exists(os.path.join(racine, MANIFESTE)):
        return _lot(racine, name)
    art = os.path.join(racine, "out", f"{name}.sol", f"{name}.json")
    src = os.path.join(racine, "src", f"{name}.sol")
    cst = os.path.join(racine, "rewards", "rewards_constants.json")
    manquants = [p for p in (art, src, cst) if not os.path.exists(p)]
    if manquants:
        raise ArtefactError(
            f"ARRÊT : ni lot publié ({MANIFESTE} absent) ni arbre `contracts/` complet sous {racine}. "
            f"Manquent : {[os.path.relpath(p, racine) for p in manquants]}.")
    return Artefacts(racine, "contracts", art, src, cst)


def lot_par_defaut():
    """Le lot embarqué avec le paquet. C'est lui qui rend le vérificateur autonome : un tiers qui
    récupère `veilleur/` a tout ce qu'il faut, sans une ligne de notre infrastructure."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")


def racine_par_defaut():
    """Lot embarqué s'il existe, sinon l'arbre `contracts/` voisin. Jamais de chemin en dur."""
    lot = lot_par_defaut()
    if os.path.exists(os.path.join(lot, MANIFESTE)):
        return lot
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "..", "..", "contracts"))
