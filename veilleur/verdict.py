"""Le feu vert : un document horodaté, signé, portant la RACINE EXACTE que le Safe s'apprête à signer.

Le veilleur n'a aucune clé de chaîne : il ne peut rien empêcher on-chain, et le présenter autrement
serait un mensonge. « Bloquer la publication » ne peut signifier qu'une chose : **le Safe s'interdit
de signer `postWeek` / `openDraw` sans un feu vert horodaté et signé du veilleur portant la racine
exacte**. C'est une règle de quorum HUMAINE. Le rôle de ce module est de la rendre vérifiable : sans
document signé pour CETTE racine, il n'y a pas de feu vert, et un document signé pour une AUTRE
racine ne peut pas être présenté pour celle-ci.

Trois verdicts, et ils ne se confondent pas (KE#105) :

  GO            code de sortie 0    — j'ai vérifié, tout est vrai, voici la racine couverte.
  REFUS         code de sortie 10   — j'ai vérifié, c'est FAUX. Motifs nommés.
  INDISPONIBLE  code de sortie 20   — je n'ai PAS pu vérifier. Ce n'est pas un feu vert dégradé.

Aucun autre code de sortie ne vaut 0. Un veilleur qui sortirait 0 sur « je n'ai pas pu vérifier »
transformerait une panne en heure calme, ce que KE#105 interdit.

Écriture ATOMIQUE et APRÈS la barrière des contrôles (KE#112) : le document n'existe sur le disque
que lorsque tout a été décidé, et il apparaît d'un seul coup.

L'ANCRE DE CONFIANCE est HORS de l'enveloppe (KE#130)
-----------------------------------------------------
Première rédaction : la signature était vérifiée contre `signature["clé_publique"]`, c'est-à-dire la
clé transportée par l'enveloppe qu'on vérifie. N'importe qui pouvait donc fabriquer un document
entièrement inventé, le signer avec SA clé, et obtenir `signature_valide: true` et un code de sortie
0 — la borne du contrôle venait du sujet contrôlé. La garantie annoncée (« le Safe s'interdit de
signer sans feu vert signé du veilleur ») ne tenait pas : l'outil que le signataire exécute
n'authentifiait personne.

`verify_envelope` exige désormais `clé_publique_attendue`, **paramètre nommé OBLIGATOIRE** (KE#62) :
aucun appelant ne peut retomber par défaut sur la clé de l'enveloppe, et une forme d'appel héritée
lève `TypeError` au lieu de s'auto-attester. La clé se lit dans un fichier d'ancrage nommé par `.env`
(`SPINDEX_ATTEST_PUBKEY_FILE`) ou passée par `--clé-publique` ; une divergence est un ARRÊT bruyant,
jamais un `False` silencieux que l'on confondrait avec « mauvaise signature ».
"""
import hashlib
import json
import os
import re
import time

from .attest import AttestKey, verify as _verify_sig

SCHEMA = "spindex-veilleur-verdict/1"
DOMAIN = b"spindex-veilleur-verdict/1\n"

GO = "GO"
REFUS = "REFUS"
INDISPONIBLE = "INDISPONIBLE"

EXIT_CODES = {GO: 0, REFUS: 10, INDISPONIBLE: 20}


class VerdictError(RuntimeError):
    pass


def canonical(doc) -> bytes:
    """Sérialisation canonique : clés triées, séparateurs fixes, UTF-8 non échappé. Deux machines qui
    signent le même document doivent produire les mêmes octets."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# Sous-ensemble du document qui doit être IDENTIQUE chez nous et chez un tiers. Volontairement
# étroit : ni horodatage, ni compteurs RPC, ni chemin local, ni texte de motif — rien de ce qui varie
# légitimement d'une machine à l'autre. Ce qui reste est la SUBSTANCE du verdict : quelle table,
# quelle racine, quel bloc d'instantané, quel verdict, et le statut de chaque contrôle.
def noyau_reproductible(doc):
    eng = dict(doc.get("engagement") or {})
    eng.pop("table_origine", None)          # un chemin local n'est pas de la substance
    return {
        "schéma": doc.get("schéma"),
        "action": doc.get("action"),
        "portée": doc.get("portée_technique"),
        "verdict": doc.get("verdict"),
        "engagement": eng,
        "contrôles": [{"id": c.get("id"), "statut": c.get("statut")}
                      for c in (doc.get("contrôles") or {}).get("contrôles", [])],
        "motifs": (doc.get("contrôles") or {}).get("motifs", []),
    }


def empreinte_reproductible(doc):
    """L'empreinte que deux exécutants indépendants doivent obtenir à l'identique."""
    return hashlib.sha256(canonical(noyau_reproductible(doc))).hexdigest()


def build(action, verdict, engagement, controls_dict, contexte, alertes=None, portée="complète"):
    if verdict not in EXIT_CODES:
        raise VerdictError(f"ARRÊT : verdict inconnu « {verdict} ».")
    if action not in ("postWeek", "openDraw"):
        raise VerdictError(f"ARRÊT : action inconnue « {action} ».")
    if verdict == GO and not engagement.get("racine"):
        raise VerdictError(
            "ARRÊT : un feu vert doit porter la RACINE EXACTE. Un GO sans racine ne couvre rien et "
            "pourrait être présenté pour n'importe quelle table.")
    now = int(time.time())
    doc = {
        "schéma": SCHEMA,
        "action": action,
        "portée_technique": portée,
        "verdict": verdict,
        "émis_le_ts": now,
        "émis_le": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "engagement": engagement,
        "contrôles": controls_dict,
        "contexte": contexte,
        "alertes": alertes or [],
        "portée": (
            "Ce document ne bloque rien techniquement : le veilleur n'a aucune clé de chaîne. Il rend "
            "opposable une règle de quorum humaine — le Safe s'interdit de signer sans un feu vert "
            "portant CETTE racine. En l'absence de feu vert, la semaine GLISSE, et le glissement doit "
            "lui-même alerter. La vérification ne portant que sur des données PUBLIQUES, n'importe "
            "qui peut la rejouer : une panne de notre instance n'est pas une panne de la garantie."
        ),
    }
    doc["empreinte_reproductible"] = empreinte_reproductible(doc)
    return doc


def sign(doc, key: AttestKey):
    payload = canonical(doc)
    sig = key.sign(DOMAIN + payload)
    return {
        "document": doc,
        "signature": {
            "alg": "ed25519",
            "domaine": DOMAIN.decode(),
            "clé_publique": key.public_hex,
            "signature": sig.hex(),
            "empreinte_document_sha256": hashlib.sha256(payload).hexdigest(),
        },
    }


def sans_signature(doc, pourquoi):
    """Enveloppe NON SIGNÉE, explicitement. Un tiers qui rejoue nos contrôles n'a pas notre clé et ne
    doit pas en fabriquer une : il produit un verdict dont la valeur est la REPRODUCTIBILITÉ, pas
    l'attestation. Le champ `signature` est volontairement ABSENT — une signature vide, un `alg:
    "aucune"` ou une chaîne de zéros finiraient par être lus comme une signature."""
    return {
        "document": doc,
        "attestation": {
            "état": "NON SIGNÉ",
            "pourquoi": pourquoi,
            "à_savoir": "ce document n'est pas un feu vert opposable. Sa valeur est que son "
                        "`empreinte_reproductible` doit égaler celle de tout autre exécutant.",
            "empreinte_reproductible": doc.get("empreinte_reproductible"),
        },
    }


_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")


class CleInattendue(VerdictError):
    """La signature est d'une AUTRE clé que l'ancre de confiance. Distinct d'une signature invalide :
    ici la cryptographie peut être parfaite, c'est le SIGNATAIRE qui n'est pas le nôtre."""


def charger_cle_de_confiance(chemin):
    """Lit l'ancre de confiance — un fichier HORS de l'enveloppe, dont le chemin vient de `.env` ou
    de la ligne de commande. Un fichier absent, vide ou mal formé est un ARRÊT : sans ancre, il n'y a
    rien à vérifier, et « je n'ai pas d'ancre » ne doit pas ressembler à « la signature est bonne »
    (KE#105 / KE#115)."""
    if not chemin:
        raise VerdictError(
            "ARRÊT : aucune clé publique de confiance. Une signature ne se vérifie pas contre la clé "
            "que l'enveloppe transporte — n'importe qui fabriquerait alors un « GO » valide. Fournir "
            "`--clé-publique <hex|fichier>` ou poser `SPINDEX_ATTEST_PUBKEY_FILE` dans `.env`.")
    val = chemin.strip()
    if _HEX32.match(val):
        return val.lower()
    if not os.path.exists(val):
        raise VerdictError(
            f"ARRÊT : ancre de confiance introuvable ({val}). Elle doit exister HORS de l'enveloppe : "
            f"c'est tout ce qui distingue un feu vert du veilleur d'un document fabriqué.")
    with open(val, "r", encoding="utf-8") as fh:
        txt = fh.read().strip()
    # tolère « 0x… », un JSON {"clé_publique": "…"} ou une ligne hexadécimale nue
    if txt.startswith("{"):
        d = json.loads(txt)
        txt = (d.get("clé_publique") or d.get("cle_publique") or d.get("public_key") or "").strip()
    if txt.lower().startswith("0x"):
        txt = txt[2:]
    if not _HEX32.match(txt):
        raise VerdictError(
            f"ARRÊT : {val} ne contient pas une clé publique Ed25519 (32 octets hexadécimaux).")
    return txt.lower()


def verify_envelope(env, *, clé_publique_attendue) -> bool:
    """Vrai seulement si l'enveloppe est signée PAR L'ANCRE ATTENDUE et que la signature tient.

    `clé_publique_attendue` est NOMMÉ et OBLIGATOIRE : c'est ce qui empêche le prochain appelant de
    réintroduire l'auto-attestation par omission (KE#62). Une clé inattendue lève `CleInattendue` et
    ne rend JAMAIS `True` — ni `False`, qui se lirait « mauvaise signature » alors que le problème
    est le signataire.
    """
    attendue = charger_cle_de_confiance(clé_publique_attendue)
    doc = env.get("document")
    if "signature" not in env:
        raise VerdictError(
            "ARRÊT : cette enveloppe n'est PAS signée (" + str((env.get("attestation") or {})
                                                               .get("état", "sans attestation"))
            + "). Elle peut être comparée par son empreinte reproductible, elle ne peut pas être "
              "présentée comme un feu vert.")
    s = env.get("signature") or {}
    if not doc or s.get("alg") != "ed25519":
        raise VerdictError("ARRÊT : enveloppe sans document ou algorithme inattendu.")
    if s.get("domaine") != DOMAIN.decode():
        raise VerdictError(
            "ARRÊT : domaine de signature différent. Une signature valide dans un autre domaine ne "
            "vaut pas ici — c'est précisément à quoi sert la séparation de domaine.")
    portée = (s.get("clé_publique") or "").strip().lower()
    if portée.startswith("0x"):
        portée = portée[2:]
    if portée != attendue:
        raise CleInattendue(
            f"ARRÊT : cette enveloppe est signée par « {portée[:16] or '(absente)'}… », l'ancre de "
            f"confiance attend « {attendue[:16]}… ». Une enveloppe qui porte sa propre clé n'atteste "
            f"rien : ce document n'est PAS un feu vert du veilleur.")
    payload = canonical(doc)
    if hashlib.sha256(payload).hexdigest() != s.get("empreinte_document_sha256"):
        return False
    # La signature est vérifiée contre l'ANCRE, jamais contre la clé de l'enveloppe.
    # REDONDANCE ASSUMÉE, et dite plutôt que revendiquée : la garde `portée != attendue` ci-dessus
    # rend les deux valeurs identiques ici, donc AUCUN test ne peut distinguer `attendue` de
    # `s["clé_publique"]` à ce point — cette ligne n'est pas une jambe indépendante et n'a pas de
    # cassure (KE#76 : on ne compte pas comme preuve ce qu'on ne peut pas faire rougir). Elle est
    # écrite ainsi pour que la suppression de la garde ne suffise pas à rétablir l'auto-attestation.
    return _verify_sig(attendue, DOMAIN + payload, bytes.fromhex(s["signature"]))


def write(env, state_dir):
    """Écrit APRÈS la barrière, ATOMIQUEMENT. Le nom porte l'action, la semaine et la racine : deux
    verdicts pour la même racine ne s'écrasent pas par accident, et un verdict pour une AUTRE racine
    est visible à l'œil nu dans le nom du fichier."""
    d = os.path.join(state_dir, "verdicts")
    os.makedirs(d, exist_ok=True)
    doc = env["document"]
    eng = doc["engagement"]
    racine = (eng.get("racine") or "0x")[2:14]
    name = f"{doc['émis_le'].replace(':', '')}-{doc['action']}-w{eng.get('weekId')}-{racine}-{doc['verdict']}.json"
    path = os.path.join(d, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=1, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path
