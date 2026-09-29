#!/usr/bin/env bash
# Le banc : il exécute `outils/executer.sh`, c est-à-dire EXACTEMENT ce que lance le job, dans cinq
# situations, et il vérifie le résultat de chacune. Il ne réécrit aucune étape — un banc qui
# reproduit les étapes à sa façon ne prouve rien du job réel.
#
# Toutes les lectures de chaîne sont en LECTURE SEULE. Aucune transaction n est émise, nulle part.
#
#   A  chaîne inattendue   le secret RPC pointe une AUTRE chaîne (4663 au lieu de 46630)   attendu ROUGE (1)
#   B  contrôle rouge      la fenêtre d état mesurée passe sous le besoin de sûreté         attendu ROUGE (1)
#   C  témoin positif      tout est normal                                                  attendu VERT  (0)
#   D  copie modifiée      un octet change dans le paquet copié                             attendu ARRET (2)
#   E  secret absent       la clé d attestation n est pas fournie                           attendu ARRET (2)
#   G  conformité          la convention merkle de la copie est celle du CONTRAT et de la famille scellée,
#                          et chaque garde de conformité REFUSE ce qu elle doit refuser (8 refus observés)
#   H  profil fournisseur  URL dRPC sans profil déclaré -> ARRET ; avec le profil de production, un faux dRPC
#                          local (18570-79) lit 1 000 blocs sans refus, et SANS la ligne de profil il refuse
#   J  publication         dépôt git LOCAL jetable : poussée réelle (0) ; origin invalide -> pousser.sh sort 1
#                          (jamais un step vert muet, KE#105) ; branche.sh distingue « absente » d « injoignable »
#   K  cache contredit     un segment figé falsifié (sha recalculé) : le différentiel D le contredit ->
#                          journaux ÉCARTÉS hors de etat/ avant publication, ARRET (2) nommé
#   L  fuite               une VRAIE passe dont l URL secrète porte un marqueur : aucun fichier écrit ou publié
#                          (lot, état, battement, health, derniere-passe) ne le contient
#   M  cadence/battements  health : période ATTENDUE 900 s et silence tiré du filet MESURÉ (≥ 32 400 s) ;
#                          le lot porte le DERNIER battement de CHAQUE tâche, octets et horodatage d origine
#   I  redéploiement       la configuration désigne un autre contrat que l état restauré : état ARCHIVÉ,
#                          ré-amorçage (refusé ici, le contrat désigné étant faux)          attendu ARRET (2)
#
# C est le TÉMOIN POSITIF (C) qui rend les autres lisibles : sans lui, un montage cassé en permanence
# afficherait quatre succès sur cinq et on appellerait ça une preuve (KE#121).
#
# A et B doivent en plus PUBLIER leur lot : un veilleur qui se tait quand il trouve quelque chose est
# pire qu un veilleur absent. Le banc le vérifie, ce n est pas une intention.
#
#   banc/preuves.sh <dossier de travail> <fichier de clé de banc>
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRAVAIL="${1:?ARRET : dossier de travail attendu}"
CLE="${2:?ARRET : fichier de cle de banc attendu (32 octets hexa, jetable)}"
RPC_VRAI="${BANC_RPC:-https://rpc.testnet.chain.robinhood.com}"
RPC_AUTRE="${BANC_RPC_AUTRE:-https://rpc.mainnet.chain.robinhood.com}"
# Filtre de jambes : les cassures synthétiques ne rejouent que la (ou les) jambe(s) qu elles visent,
# pour que « rouge sur le test NOMMÉ » veuille dire quelque chose. Par défaut : toutes.
JAMBES="${BANC_JAMBES:-temoin chaine controle sceau secret autonome conformite profil redeploiement publication cache_contredit fuite cadence}"
# Racine du PROJET (arbre source + frozen.py) : les contrôles de conformité à la SOURCE en ont besoin.
PROJET="${BANC_PROJET:-$(dirname "$RACINE")}"
voulue() { [[ " $JAMBES " == *" $1 "* ]]; }

export PYTHONDONTWRITEBYTECODE=1
find "$RACINE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Le banc lit la chaîne par le nœud OFFICIEL, pas par dRPC (un amorçage à 101 blocs par requête prendrait des
# heures) : sa configuration est celle de production à UNE clé près, `rpc_profil`, qui doit désigner le
# fournisseur réellement en face — sinon `preparer.py` refuse, et c'est la garde de la jambe H.
CONFIG_BANC="$TRAVAIL/config-banc.json"
mkdir -p "$TRAVAIL"
python3 -B - "$RACINE/config/chaine-46630.json" "$CONFIG_BANC" "$RPC_VRAI" "$RACINE" <<'PYEOF'
import json, sys
sys.path.insert(0, sys.argv[4])
from veilleur.fournisseurs import PROFILS
from urllib.parse import urlparse
dom = lambda u: ".".join((urlparse(u).hostname or "").split(".")[-2:])
c = json.load(open(sys.argv[1], encoding="utf-8"))
p = [n for n, v in PROFILS.items() if dom(v["url"]) == dom(sys.argv[3])]
if p: c["rpc_profil"] = p[0]
else: c.pop("rpc_profil", None)
json.dump(c, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF

VERTS=0
ROUGES=0
declare -a ECHECS=()

etat_de_reference() {   # un état déjà amorcé, pour ne pas relire toute la chaîne à chaque jambe
  if [ ! -f "$TRAVAIL/reference/etat/amorcage.json" ]; then
    echo "  (amorçage de référence : lecture complète de la chaîne, une seule fois)"
    mkdir -p "$TRAVAIL/reference"
    B_ETAT="$TRAVAIL/reference" B_LOT="$TRAVAIL/reference/lot" B_TACHE=passe B_CONFIG="$CONFIG_BANC" \
    SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
      bash "$RACINE/outils/executer.sh" > "$TRAVAIL/reference.log" 2>&1 \
      || { echo "ARRET : l amorçage de référence a échoué, voir $TRAVAIL/reference.log" >&2; exit 2; }
  fi
}

# jambe <nom> <attendu> <config> <rpc> <cle|VIDE> [lot_exige]
jambe() {
  local nom="$1" attendu="$2" config="$3" rpc="$4" cle="$5" lot_exige="${6:-non}"
  local d="$TRAVAIL/$nom"
  rm -rf "$d" && mkdir -p "$d"
  cp -r "$TRAVAIL/reference/etat" "$d/etat"
  rm -f "$d/etat/battement-passe.json"   # le compteur repart, la jambe de progression reste exigeante
  local code=0
  B_ETAT="$d" B_LOT="$d/lot" B_TACHE=passe B_CONFIG="$config" \
  SPINDEX_B_RPC_URL="$rpc" SPINDEX_B_ATTEST_KEY_HEX="$cle" \
    bash "$RACINE/outils/executer.sh" > "$d.log" 2>&1 || code=$?
  if [ "$code" = "$attendu" ]; then
    echo "  [$nom] OK — code $code (attendu $attendu)"
    VERTS=$((VERTS + 1))
  else
    echo "  [$nom] ÉCHEC — code $code, attendu $attendu (voir $d.log)"
    ECHECS+=("$nom: code $code au lieu de $attendu")
    ROUGES=$((ROUGES + 1))
  fi
  if [ "$lot_exige" = "lot" ]; then
    if [ -f "$d/lot/SIGNATURE.json" ] && [ -f "$d/lot/JUGEMENT.json" ]; then
      local v
      v="$(python3 -B -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["verdict"])' "$d/lot/JUGEMENT.json")"
      if [ "$v" = "ROUGE" ]; then
        echo "  [$nom] OK — le lot a été PUBLIÉ et SIGNÉ malgré le rouge, jugement $v"
        VERTS=$((VERTS + 1))
      else
        echo "  [$nom] ÉCHEC — lot publié mais jugement « $v », attendu ROUGE"
        ECHECS+=("$nom: jugement $v au lieu de ROUGE")
        ROUGES=$((ROUGES + 1))
      fi
    else
      echo "  [$nom] ÉCHEC — aucun lot signé publié : le veilleur s est tu en trouvant quelque chose"
      ECHECS+=("$nom: pas de lot publié")
      ROUGES=$((ROUGES + 1))
    fi
  fi
}

motif_present() {   # <nom> <clé de motif attendue>
  local d="$TRAVAIL/$1" attendu="$2"
  local vu
  vu="$(python3 -B -c '
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
print(",".join(m["cle"] for m in d.get("motifs") or []))' "$d/lot/JUGEMENT.json" 2>/dev/null)"
  if [[ ",$vu," == *",$attendu,"* ]]; then
    echo "  [$1] OK — motif « $attendu » nommé (motifs : $vu)"
    VERTS=$((VERTS + 1))
  else
    echo "  [$1] ÉCHEC — motif « $attendu » absent (motifs : ${vu:-aucun})"
    ECHECS+=("$1: motif $attendu absent")
    ROUGES=$((ROUGES + 1))
  fi
}

echo "=== banc du veilleur b — lecture seule, aucune transaction ==="
etat_de_reference

if voulue temoin; then
echo
echo "--- C : témoin positif (tout est normal) — SANS lui, les autres jambes ne valent rien"
jambe temoin 0 "$CONFIG_BANC" "$RPC_VRAI" "$(cat "$CLE")"
fi

if voulue chaine; then
echo
echo "--- A : le secret RPC pointe une AUTRE chaîne (4663) — refus bruyant attendu"
jambe chaine 1 "$CONFIG_BANC" "$RPC_AUTRE" "$(cat "$CLE")" lot
motif_present chaine chaine_inattendue
fi

if voulue controle; then
echo
echo "--- B : contrôle ROUGE (fenêtre d état sous le besoin de sûreté) — le job doit échouer"
fi
python3 -B - "$CONFIG_BANC" "$TRAVAIL/config-besoin-haut.json" <<'PYEOF'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
# Besoin de sûreté porté à 3000 s : la fenêtre RÉELLE de la 46630 se mesure autour de 1 200-1 400 s,
# donc le paquet scellé rend « fenêtre_sous_besoin » en P0. Les trois réglages restent cohérents
# (besoin >= consigne, seuil >= besoin), sinon la configuration serait refusée au chargement et on
# testerait un refus de configuration au lieu d un contrôle rouge.
c["window_need_s"] = 3000
c["window_alert_s"] = 4500
c["publish_deadline_s"] = 300
json.dump(c, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
if voulue controle; then
jambe controle 1 "$TRAVAIL/config-besoin-haut.json" "$RPC_VRAI" "$(cat "$CLE")" lot
motif_present controle controle_rouge
fi

if voulue sceau; then
echo
echo "--- D : un octet modifié dans la copie du paquet scellé"
cp "$RACINE/veilleur/merkle.py" "$TRAVAIL/merkle.py.sauve"
printf '\n# octet de banc\n' >> "$RACINE/veilleur/merkle.py"
jambe sceau 2 "$CONFIG_BANC" "$RPC_VRAI" "$(cat "$CLE")"
cp "$TRAVAIL/merkle.py.sauve" "$RACINE/veilleur/merkle.py"
python3 -B "$RACINE/outils/sceau.py" vérifier >/dev/null \
  && echo "  [sceau] OK — la copie est restaurée à l identique" \
  || { echo "  [sceau] ÉCHEC — la copie n a PAS été restaurée"; ECHECS+=("sceau: restauration"); ROUGES=$((ROUGES+1)); }
fi

if voulue secret; then
echo
echo "--- E : la clé d attestation n est pas fournie"
jambe secret 2 "$CONFIG_BANC" "$RPC_VRAI" ""
fi

if voulue autonome; then
echo
echo "--- F : le vérificateur de lot tourne SEUL, sans paquet veilleur — la situation de la surveillance"
# Sur la machine de surveillance il n y a pas de paquet `veilleur` : elle tire la branche et lance
# `verifier_lot.py`, point. Si ce fichier importait le paquet, la vérification échouerait là-bas et
# nulle part ici — le genre de défaut qui ne se voit qu en production.
SEUL="$TRAVAIL/comme-la-surveillance"
rm -rf "$SEUL" && mkdir -p "$SEUL"
cp "$RACINE/outils/verifier_lot.py" "$SEUL/"
cp -r "$TRAVAIL/temoin/lot" "$SEUL/courant"
ANCRE="$TRAVAIL/temoin/attest-b.pub"
if ( cd "$SEUL" && python3 -B verifier_lot.py --lot courant --clé-publique "$ANCRE" >/dev/null 2>"$TRAVAIL/autonome.err" ); then
  echo "  [autonome] OK — le lot se vérifie sans rien d autre que cryptography"
  VERTS=$((VERTS + 1))
else
  echo "  [autonome] ÉCHEC — $(head -2 "$TRAVAIL/autonome.err" | tr "\n" " ")"
  ECHECS+=("autonome: verifier_lot.py ne tourne pas seul")
  ROUGES=$((ROUGES + 1))
fi
# Sans ancre : REFUS, jamais un repli sur la clé que le lot transporte (KE#130).
# CET ESSAI VIENT AVANT la corruption, et c est tout le sujet : une cassure synthétique a montré
# qu il passait « pour la mauvaise raison » quand le lot était déjà abîmé — il refusait à cause de
# l empreinte, pas à cause de l ancre manquante, et la garde de l ancre était donc décorative.
if ( cd "$SEUL" && python3 -B verifier_lot.py --lot courant >/dev/null 2>&1 ); then
  echo "  [autonome] ÉCHEC — vérifie un lot INTACT sans ancre de confiance"
  ECHECS+=("autonome: accepte sans ancre")
  ROUGES=$((ROUGES + 1))
else
  echo "  [autonome] OK — sur un lot INTACT, sans ancre de confiance, il REFUSE"
  VERTS=$((VERTS + 1))
fi
# TÉMOIN NÉGATIF (KE#121) : un vérificateur qu on n a jamais vu dire non ne prouve rien.
printf "\n" >> "$SEUL/courant/health.json"
if ( cd "$SEUL" && python3 -B verifier_lot.py --lot courant --clé-publique "$ANCRE" >/dev/null 2>&1 ); then
  echo "  [autonome] ÉCHEC — un octet ajouté à health.json passe quand même"
  ECHECS+=("autonome: octet modifié accepté")
  ROUGES=$((ROUGES + 1))
else
  echo "  [autonome] OK — un octet ajouté à health.json est REFUSÉ"
  VERTS=$((VERTS + 1))
fi
fi


if voulue conformite; then
echo
echo "--- G : la convention de la copie est celle de la SOURCE (KE#130/#137/#148) — et chaque garde sait dire NON"
[ -f "$PROJET/contracts/script/frozen.py" ] || { echo "ARRET : BANC_PROJET ($PROJET) n est pas la racine du projet" >&2; exit 2; }
CF=(python3 -B "$RACINE/outils/conformite.py")
G="$TRAVAIL/conformite"; rm -rf "$G" && mkdir -p "$G"
# attendu <nom> <code attendu> <motif attendu dans la sortie | -> <commande…>
attendu() {
  local nom="$1" want="$2" motif="$3"; shift 3
  local code=0
  "$@" > "$G/$nom.log" 2>&1 || code=$?
  if [ "$code" != "$want" ]; then
    echo "  [conformite:$nom] ÉCHEC — code $code, attendu $want (voir $G/$nom.log)"
    ECHECS+=("conformite:$nom: code $code au lieu de $want"); ROUGES=$((ROUGES + 1)); return
  fi
  # le MOTIF, pas seulement le code : un refus pour une autre raison laisserait la garde visée morte (KE#139)
  if [ "$motif" != "-" ] && ! grep -qF -- "$motif" "$G/$nom.log"; then
    echo "  [conformite:$nom] ÉCHEC — code $code mais motif « $motif » absent (voir $G/$nom.log)"
    ECHECS+=("conformite:$nom: motif absent"); ROUGES=$((ROUGES + 1)); return
  fi
  echo "  [conformite:$nom] OK — code $code${motif:+ ; motif « $motif »}"
  VERTS=$((VERTS + 1))
}
# témoins POSITIFS d abord (KE#121) : sans eux, six refus pourraient venir d un outil en panne
attendu temoin-copie     0 "CONVENTION CONFORME" "${CF[@]}" vérifier
attendu temoin-generateur 0 "VECTEURS = GÉNÉRATEUR" "${CF[@]}" contrôler-générateur --projet "$PROJET"
attendu temoin-source    0 "SOURCE RECOUPÉE" "${CF[@]}" recouper-source --projet "$PROJET"

# R1 — une feuille de référence falsifiée : la copie ne doit PAS « tomber dessus »
python3 -B - "$RACINE/config/vecteurs-convention.json" "$G/vecteurs-falsifies.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
f = d["vecteurs"]["draw"][3]["feuille"]
d["vecteurs"]["draw"][3]["feuille"] = f[:-1] + ("0" if f[-1] != "0" else "1")
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
attendu R1-feuille-falsifiee 2 "draw[3] : copie" "${CF[@]}" vérifier --vecteurs "$G/vecteurs-falsifies.json"

# R2 — le CONTRAT passe à une autre étiquette (v2), constantes cohérentes : le fichier de vecteurs
#      n est plus ce que son générateur produit aujourd hui (KE#148)
FP="$G/projet-v2"; mkdir -p "$FP/contracts/src" "$FP/contracts/rewards"
sed 's#SPINDEX/rewards/draw/v1#SPINDEX/rewards/draw/v2#' "$PROJET/contracts/src/SpindexRewards.sol" > "$FP/contracts/src/SpindexRewards.sol"
python3 -B - "$PROJET/contracts/rewards/rewards_constants.json" "$FP/contracts/rewards/rewards_constants.json" "$(~/.foundry/bin/cast keccak SPINDEX/rewards/draw/v2 2>/dev/null || cast keccak SPINDEX/rewards/draw/v2)" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
d["merkle"]["draw_tag"] = 'keccak256("SPINDEX/rewards/draw/v2") = ' + sys.argv[3]
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
attendu R2-source-a-change 2 "ne correspond plus à ce que son générateur" "${CF[@]}" contrôler-générateur --projet "$FP"

# R3 — l autorité amont (contracts/rewards) diverge de la copie et de la famille
# Projet miroir par liens : TOUT est le vrai projet, sauf le seul fichier muté. Un miroir partiel
# faisait refuser le scellé de la famille (rapports absents) — refus pour une AUTRE raison, vu par le
# contrôle du motif (KE#139).
AP="$G/projet-amont"; mkdir -p "$AP/contracts/rewards"
for e in "$PROJET"/* "$PROJET"/.[!.]*; do [ -e "$e" ] && [ "$(basename "$e")" != contracts ] && ln -s "$e" "$AP/$(basename "$e")"; done
for e in "$PROJET"/contracts/*; do [ "$(basename "$e")" != rewards ] && ln -s "$e" "$AP/contracts/$(basename "$e")"; done
for e in "$PROJET"/contracts/rewards/*; do [ "$(basename "$e")" != rewards_constants.json ] && ln -s "$e" "$AP/contracts/rewards/$(basename "$e")"; done
python3 -B - "$PROJET/contracts/rewards/rewards_constants.json" "$AP/contracts/rewards/rewards_constants.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
d["merkle"]["odd_node"] = "dupliqué"
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
attendu R3-amont-diverge 2 "les conventions divergent" "${CF[@]}" recouper-source --projet "$AP"

# R4 — une copie PÉRIMÉE (le FIGE.json d avant la séparation de domaine) : c est l incident du 2026-09-24
CP="$G/copie-perimee"; mkdir -p "$CP"
( cd "$RACINE" && tar --exclude=.git --exclude=__pycache__ -cf - . ) | ( cd "$CP" && tar -xf - )
git -C "$RACINE" show 2d27635:veilleur/FIGE.json > "$CP/veilleur/FIGE.json"
attendu R4-copie-perimee 2 "la copie est PÉRIMÉE" python3 -B "$CP/outils/conformite.py" recouper-source --projet "$PROJET"

# R5 — une copie SANS étiquette de domaine : refus, ET nommé comme la collision F03
python3 -B - "$CP/veilleur/merkle.py" <<'PYEOF'
import sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read()
s2 = s.replace("inner = keccak256(_enc_bytes32(TAG_CLAIM) + enc_address(player)", "inner = keccak256(enc_address(player)")
assert s2 != s, "R5 : la mutation n a rien changé"
open(p, "w", encoding="utf-8").write(s2)
PYEOF
attendu R5-sans-etiquette 2 "collision F03" python3 -B "$CP/outils/conformite.py" vérifier

# R7 — COUVERTURE (KE#111) : un domaine de paiement sans aucun vecteur ne passe pas « sans faute »
python3 -B - "$RACINE/config/vecteurs-convention.json" "$G/vecteurs-sans-draw.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8")); d["vecteurs"]["draw"] = []
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
attendu R7-domaine-vide 2 "aucun vecteur exercé pour ['draw']" "${CF[@]}" vérifier --vecteurs "$G/vecteurs-sans-draw.json"

# R8 — des vecteurs générés pour une AUTRE convention que celle embarquée : on ne compare pas deux mondes
python3 -B - "$RACINE/config/vecteurs-convention.json" "$G/vecteurs-autre-convention.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8")); d["convention_sha256"] = "0" * 64
json.dump(d, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
attendu R8-autre-convention 2 "n'est PAS celle pour laquelle" "${CF[@]}" vérifier --vecteurs "$G/vecteurs-autre-convention.json"

# R6 — le JOB lui-même refuse de lire la chaîne quand la copie n est pas conforme (sortie 2, avant l étape 2)
# état amorcé repris de la référence : si la garde tombe (cassure), le job ne relit pas toute la chaîne
# pendant vingt minutes — il fait une passe tiède et sort 0, ce qui suffit à le voir.
mkdir -p "$G/job" && cp -r "$TRAVAIL/reference/etat" "$G/job/etat" && rm -f "$G/job/etat/battement-passe.json"
code=0
B_ETAT="$G/job" B_VECTEURS="$G/vecteurs-falsifies.json" SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  bash "$RACINE/outils/executer.sh" > "$G/R6-job.log" 2>&1 || code=$?
if [ "$code" = 2 ] && grep -qF "ne calcule pas les feuilles" "$G/R6-job.log" && ! grep -qF -- "--- 2/6" "$G/R6-job.log"; then
  echo "  [conformite:R6-job] OK — le job s arrête (2) avant toute lecture de chaîne"
  VERTS=$((VERTS + 1))
else
  echo "  [conformite:R6-job] ÉCHEC — code $code (voir $G/R6-job.log)"
  ECHECS+=("conformite:R6-job: code $code"); ROUGES=$((ROUGES + 1))
fi
fi

if voulue profil; then
echo
echo "--- H : profil du fournisseur — b est sur dRPC (101 blocs par plage, refus en HTTP 400)"
H="$TRAVAIL/profil"; rm -rf "$H" && mkdir -p "$H"
python3 -B - "$RACINE/config/chaine-46630.json" "$H/config-sans-profil.json" <<'PYEOF'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8")); c.pop("rpc_profil", None)
json.dump(c, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
code=0
SPINDEX_B_RPC_URL="https://robinhood-testnet.drpc.org" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  python3 -B "$RACINE/outils/preparer.py" --config "$H/config-sans-profil.json" --etat "$H/sans" > "$H/H1.log" 2>&1 || code=$?
if [ "$code" = 2 ] && grep -qF "AUCUN profil" "$H/H1.log"; then
  echo "  [profil:H1] OK — URL dRPC sans profil déclaré : ARRET nommé"; VERTS=$((VERTS + 1))
else
  echo "  [profil:H1] ÉCHEC — code $code (voir $H/H1.log)"; ECHECS+=("profil:H1 code $code"); ROUGES=$((ROUGES + 1))
fi
code=0
SPINDEX_B_RPC_URL="https://robinhood-testnet.drpc.org" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  python3 -B "$RACINE/outils/preparer.py" --config "$RACINE/config/chaine-46630.json" --etat "$H/prod" > "$H/H2.log" 2>&1 || code=$?
if [ "$code" = 0 ]; then
  python3 -B "$RACINE/outils/banc_fournisseur.py" --env "$H/prod/veilleur-b.env" >> "$H/H2.log" 2>&1 || code=$?
fi
# rôles séparés : journaux = le secret, état = le RPC public de la configuration, et AUCUN mode mono en plus
if [ "$code" = 0 ] && ! { grep -q "^SPINDEX_RPC_URL_JOURNAUX='https://robinhood-testnet.drpc.org'" "$H/prod/veilleur-b.env" \
     && grep -q "^SPINDEX_RPC_URL_ETAT='https://rpc.testnet.chain.robinhood.com'" "$H/prod/veilleur-b.env" \
     && ! grep -q "^SPINDEX_RPC_URL=" "$H/prod/veilleur-b.env"; }; then
  code=9; echo "rôles non séparés dans le .env écrit" >> "$H/H2.log"
fi
if [ "$code" = 0 ] && grep -qF "PROFIL PORTANT" "$H/H2.log"; then
  echo "  [profil:H2] OK — $(grep -F "PROFIL PORTANT" "$H/H2.log")"; VERTS=$((VERTS + 1))
else
  echo "  [profil:H2] ÉCHEC — code $code : $(tail -3 "$H/H2.log" | tr "\n" " ")"; ECHECS+=("profil:H2"); ROUGES=$((ROUGES + 1))
fi
fi

if voulue redeploiement; then
echo
echo "--- I : la configuration désigne un AUTRE déploiement que l état restauré (redéploiement)"
python3 -B - "$CONFIG_BANC" "$TRAVAIL/config-autre-deploiement.json" <<'PYEOF'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8")); c["rewards"] = "0x" + "ab" * 20
json.dump(c, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
jambe redeploiement 2 "$TRAVAIL/config-autre-deploiement.json" "$RPC_VRAI" "$(cat "$CLE")"
if grep -qF "NOUVEAU DÉPLOIEMENT" "$TRAVAIL/redeploiement.log" && ls -d "$TRAVAIL/redeploiement"/etat-archive-0x* >/dev/null 2>&1 \
   && grep -qF "amorçage refusé" "$TRAVAIL/redeploiement.log"; then
  echo "  [redeploiement] OK — ancien état ARCHIVÉ, ré-amorçage tenté et refusé sur le faux contrat"; VERTS=$((VERTS + 1))
else
  echo "  [redeploiement] ÉCHEC — archive ou ré-amorçage absent (voir $TRAVAIL/redeploiement.log)"
  ECHECS+=("redeploiement: pas d archive / pas de ré-amorçage"); ROUGES=$((ROUGES + 1))
fi
fi

if voulue publication; then
echo
echo "--- J : publication sur « attestations » — un échec de poussée fait échouer le step (KE#105)"
J="$TRAVAIL/publication"; rm -rf "$J" && mkdir -p "$J"
jj() {   # jj <nom> <code attendu> <motif|-> <commande…>
  local nom="$1" want="$2" motif="$3"; shift 3; local code=0
  "$@" > "$J/$nom.log" 2>&1 || code=$?
  if [ "$code" = "$want" ] && { [ "$motif" = "-" ] || grep -qF -- "$motif" "$J/$nom.log"; }; then
    echo "  [publication:$nom] OK — code $code"; VERTS=$((VERTS + 1))
  else
    echo "  [publication:$nom] ÉCHEC — code $code, attendu $want / « $motif » (voir $J/$nom.log)"
    ECHECS+=("publication:$nom"); ROUGES=$((ROUGES + 1))
  fi
}
(
  set -e
  git init -q --bare "$J/origine.git"
  git init -q "$J/graine" && cd "$J/graine" && git config user.email b@banc && git config user.name banc
  git checkout -q --orphan attestations && echo 0 > n && git add n && git commit -qm graine
  git push -q "$J/origine.git" attestations
  git init -q "$J/depot" && cd "$J/depot" && git config user.email b@banc && git config user.name banc
  echo x > f && git add f && git commit -qm depot && git remote add origin "$J/origine.git"
) > "$J/prepa.log" 2>&1 || { echo "ARRET : préparation du dépôt jetable impossible (voir $J/prepa.log)" >&2; exit 2; }
# J1 témoin positif : la branche existe -> worktree ; commit ; poussée RÉELLE -> 0, et le commit est chez origin
jj J1-branche-existante 0 "branche existante" bash -c "cd '$J/depot' && bash '$RACINE/outils/branche.sh' attestations publication"
( cd "$J/depot/publication" && echo 1 > n && git -c user.email=b@banc -c user.name=banc commit -qam lot ) > /dev/null 2>&1
B_ATTENTE_POUSSEE_S=0 jj J1-poussee 0 "lot publié" bash "$RACINE/outils/pousser.sh" "$J/depot/publication" "lot"
if [ "$(git -C "$J/origine.git" log -1 --format=%s attestations 2>/dev/null)" = "lot" ]; then
  echo "  [publication:J1-chez-origin] OK — le lot est bien sur la branche distante"; VERTS=$((VERTS + 1))
else
  echo "  [publication:J1-chez-origin] ÉCHEC — le lot n est pas chez origin"; ECHECS+=("publication:J1-chez-origin"); ROUGES=$((ROUGES + 1))
fi
# J2 : origin invalide -> la poussée échoue 3 fois -> SORTIE 1 nommée (avant : step vert, rien publié)
( cd "$J/depot/publication" && echo 2 > n && git -c user.email=b@banc -c user.name=banc commit -qam lot2 ) > /dev/null 2>&1
git -C "$J/depot/publication" remote set-url origin "$J/n-existe-pas.git"
B_ATTENTE_POUSSEE_S=0 jj J2-origin-invalide 1 "lot NON publié sur attestations après 3 essais" bash "$RACINE/outils/pousser.sh" "$J/depot/publication" "lot"
# J3 : branche.sh contre un origin injoignable -> ARRÊT (2), jamais une branche orpheline « neuve »
jj J3-injoignable 2 "injoignable" bash -c "cd '$J/depot' && bash '$RACINE/outils/branche.sh' attestations publication3"
# J4 : origin joignable, branche absente -> branche NEUVE (0)
git -C "$J/depot" remote set-url origin "$J/origine.git"
jj J4-branche-absente 0 "branche NEUVE" bash -c "cd '$J/depot' && bash '$RACINE/outils/branche.sh' autre-branche publication4"
# J5 : amorçage interrompu -> l état PARTIEL (segments figés) est poussé, pour reprise au job suivant
mkdir -p "$J/travail/etat/journaux"
printf '{"segments":[{"de":1,"à":123}]}' > "$J/travail/etat/journaux/curseur.json"
jj J5-branche 0 "branche existante" bash -c "cd '$J/depot' && bash '$RACINE/outils/branche.sh' attestations publication5"
jj J5-etat-partiel 0 "figés jusqu'au bloc 123" bash -c "cd '$J/depot' && git -C publication5 config user.email b@banc && git -C publication5 config user.name banc && bash '$RACINE/outils/etat_partiel.sh' '$J/travail' publication5"
B_ATTENTE_POUSSEE_S=0 jj J5-poussee 0 "état partiel publié" bash "$RACINE/outils/pousser.sh" "$J/depot/publication5" "état partiel"
if git -C "$J/origine.git" show attestations:etat/journaux/curseur.json 2>/dev/null | grep -qF '"à":123' \
   && git -C "$J/origine.git" log -1 --format=%s attestations | grep -qF "ÉTAT PARTIEL"; then
  echo "  [publication:J5-chez-origin] OK — curseur partiel sur la branche distante, commit marqué ÉTAT PARTIEL"; VERTS=$((VERTS + 1))
else
  echo "  [publication:J5-chez-origin] ÉCHEC — état partiel absent de origin"; ECHECS+=("publication:J5-chez-origin"); ROUGES=$((ROUGES + 1))
fi
# J6 : rien de figé -> rien à sauver (3), pas un commit vide présenté comme un état
rm -rf "$J/travail-vide" && mkdir -p "$J/travail-vide/etat"
jj J6-rien-a-sauver 3 "rien à sauver" bash -c "cd '$J/depot' && bash '$RACINE/outils/etat_partiel.sh' '$J/travail-vide' publication5"
# J7 : l arbre de publication n est pas inscriptible -> ÉCHEC (1), jamais confondu avec « rien à sauver » (3)
chmod a-w "$J/depot/publication5"
jj J7-non-inscriptible 1 "impossible" bash -c "cd '$J/depot' && bash '$RACINE/outils/etat_partiel.sh' '$J/travail' publication5"
chmod u+w "$J/depot/publication5"
# J8 : un fichier de type secret dans l état -> publication REFUSÉE (1), fichier nommé
rm -rf "$J/travail-secret" && cp -r "$J/travail" "$J/travail-secret" && echo 00 > "$J/travail-secret/etat/attest-b.hex"
jj J8-secret-refuse 1 "publication REFUSÉE" bash -c "cd '$J/depot' && bash '$RACINE/outils/etat_partiel.sh' '$J/travail-secret' publication5"
fi

if voulue cache_contredit; then
echo
echo "--- K : un cache CONTREDIT par la chaîne est écarté avant publication (sinon refus éternel)"
K="$TRAVAIL/cache_contredit"; rm -rf "$K" && mkdir -p "$K"
cp -r "$TRAVAIL/reference/etat" "$K/etat"
rm -f "$K/etat/amorcage.json" "$K/etat/battement-passe.json"
python3 -B - "$K/etat/journaux" <<'PYEOF'
import hashlib, json, os, sys
d = sys.argv[1]; cur = json.load(open(os.path.join(d, "curseur.json"), encoding="utf-8"))
m = cur["segments"][-1]; p = os.path.join(d, m["fichier"])
seg = json.load(open(p, encoding="utf-8"))
assert seg["journaux"], "segment sans journal : rien à falsifier"
seg["journaux"] = seg["journaux"][:-1]                      # un journal RETIRÉ du cache
json.dump(seg, open(p, "w", encoding="utf-8"), ensure_ascii=False)
m["n"] = len(seg["journaux"]); m["sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()   # sha RECALCULÉ
json.dump(cur, open(os.path.join(d, "curseur.json"), "w", encoding="utf-8"), ensure_ascii=False)
PYEOF
code=0
B_ETAT="$K" B_LOT="$K/lot" B_TACHE=passe B_CONFIG="$CONFIG_BANC" SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  bash "$RACINE/outils/executer.sh" > "$K.log" 2>&1 || code=$?
if [ "$code" = 2 ] && grep -qF "CONTREDIT" "$K.log" && [ ! -d "$K/etat/journaux" ] && ls -d "$K"/journaux-rejete-* >/dev/null 2>&1 \
   && python3 -B -c 'import json,sys;a=json.load(open(sys.argv[1]));sys.exit(0 if a["différentiel_D"]=="DIVERGENT" else 1)' "$K/ARRET.json"; then
  echo "  [cache_contredit] OK — D DIVERGENT, journaux écartés hors de etat/, ARRET (2) nommé"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — code $code (voir $K.log)"; ECHECS+=("cache_contredit: code $code"); ROUGES=$((ROUGES + 1))
fi
code=0; bash "$RACINE/outils/etat_partiel.sh" "$K" "$K/pub-inexistant" > "$K.ep.log" 2>&1 || code=$?
if [ "$code" = 3 ]; then
  echo "  [cache_contredit] OK — l état partiel n a plus rien à republier"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — etat_partiel rend $code (attendu 3)"; ECHECS+=("cache_contredit: republiable"); ROUGES=$((ROUGES + 1))
fi
fi

if voulue fuite; then
echo
echo "--- L : l URL secrète ne sort dans AUCUN fichier écrit ou publié (fichiers, pas déclaration — KE#129)"
MARQ="fuitebanc$(date +%s%N)"
jambe fuite 0 "$CONFIG_BANC" "${RPC_VRAI}/?cle=${MARQ}" "$(cat "$CLE")"
N="$(find "$TRAVAIL/fuite/etat" "$TRAVAIL/fuite/lot" -type f | wc -l)"
if [ "$N" -ge 5 ] && [ -f "$TRAVAIL/fuite/etat/health.json" ] && [ -f "$TRAVAIL/fuite/etat/battement-passe.json" ] \
   && [ -f "$TRAVAIL/fuite/etat/derniere-passe.json" ] && ! grep -rqF "$MARQ" "$TRAVAIL/fuite/etat" "$TRAVAIL/fuite/lot" "$TRAVAIL/fuite.log"; then
  echo "  [fuite] OK — $N fichiers relus, marqueur absent partout"; VERTS=$((VERTS + 1))
else
  echo "  [fuite] ÉCHEC — marqueur trouvé ou couverture insuffisante ($N fichiers) : $(grep -rlF "$MARQ" "$TRAVAIL/fuite/etat" "$TRAVAIL/fuite/lot" 2>/dev/null | head -3 | tr '\n' ' ')"
  ECHECS+=("fuite"); ROUGES=$((ROUGES + 1))
fi
fi

if voulue cadence; then
echo
echo "--- M : deux bornes nommées (période attendue / silence du filet mesuré) et un battement par tâche dans le lot"
M="$TRAVAIL/cadence-lot"; rm -rf "$M" && mkdir -p "$M"
jambe cadence 0 "$CONFIG_BANC" "$RPC_VRAI" "$(cat "$CLE")"
if python3 -B - "$TRAVAIL/cadence/etat/health.json" <<'PYEOF'
import json, sys
t = json.load(open(sys.argv[1], encoding="utf-8"))["taches"]
p, q, c = t["passe"], t["differentiel-quotidien"], t["differentiel-complet"]
ok = (p["période_attendue_s"] == 900 and p["silence_max_s"] >= 32400 and "filet MESURÉ" in p["silence_max_source"]
      and q["planifiée"] and q["période_s"] == 86400 and "SEUL" in (q.get("déclencheur") or "")
      and c["planifiée"] is False)
print(p["période_attendue_s"], p["silence_max_s"], q["période_s"], c["planifiée"])
sys.exit(0 if ok else 1)
PYEOF
then echo "  [cadence] OK — passe 900 s attendue / silence ≥ 32 400 s (filet mesuré) ; quotidien 86 400 s externe ; complet non planifié"; VERTS=$((VERTS + 1))
else echo "  [cadence] ÉCHEC — bornes publiées incorrectes"; ECHECS+=("cadence: bornes"); ROUGES=$((ROUGES + 1)); fi
# le lot publié PAR LE JOB (executer.sh -> publier.py), avec l index EXIGÉ de tout lot : c est le
# VÉRIFICATEUR qui doit dire si l index manque — indépendamment de tout contrôle du banc (KE#139)
if ( cd "$TRAVAIL/cadence" && SPINDEX_B_INDEX_EXIGE_DEPUIS=0 python3 -B "$RACINE/outils/verifier_lot.py" --lot lot --clé-publique "$TRAVAIL/cadence/attest-b.pub" > "$TRAVAIL/cadence-verif.log" 2>&1 ); then
  echo "  [cadence] OK — lot publié par le job accepté par le vérificateur, index EXIGÉ"; VERTS=$((VERTS + 1))
else echo "  [cadence] ÉCHEC — vérificateur : $(head -1 "$TRAVAIL/cadence-verif.log")"; ECHECS+=("cadence: index exigé"); ROUGES=$((ROUGES + 1)); fi
# un battement ANCIEN d une autre tâche dans l état : il doit sortir dans le lot tel quel, horodatage d origine
cp -r "$TRAVAIL/cadence/etat" "$M/etat"
python3 -B - "$M/etat/battement-differentiel-quotidien.json" <<'PYEOF'
import json, sys
json.dump({"format": 1, "service": "veilleur", "instance": "b", "tache": "differentiel-quotidien", "ts": 1790000000,
           "passe": 7, "bloc": 1, "resultat": "ok", "code": None, "detail": None, "empreinte": "0" * 64,
           "rpc": {}, "fournisseurs": None}, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False)
PYEOF
code=0
python3 -B "$RACINE/outils/publier.py" --etat "$M/etat" --lot "$M/lot" --cle "$TRAVAIL/cadence/attest-b.hex" \
  --sceau "$RACINE/SCEAU.json" --jugement "$TRAVAIL/cadence/lot/JUGEMENT.json" --config "$CONFIG_BANC" > "$M/publier.log" 2>&1 || code=$?
if [ "$code" = 0 ] && cmp -s "$M/etat/battement-differentiel-quotidien.json" "$M/lot/battement-differentiel-quotidien.json" \
   && python3 -B - "$M/lot/MANIFESTE.json" <<'PYEOF'
import json, sys
b = json.load(open(sys.argv[1], encoding="utf-8"))["battements"]
ok = (set(b) == {"passe", "differentiel-quotidien", "differentiel-complet"}
      and b["differentiel-quotidien"]["présent"] and b["differentiel-quotidien"]["ts_origine"] == 1790000000
      and b["passe"]["présent"] and b["differentiel-complet"]["présent"] is False)
sys.exit(0 if ok else 1)
PYEOF
then
  if ( cd "$M" && python3 -B "$RACINE/outils/verifier_lot.py" --lot lot --clé-publique "$TRAVAIL/cadence/attest-b.pub" >/dev/null 2>&1 ); then
    echo "  [cadence] OK — lot : 3 tâches indexées, battement quotidien d origine (ts 1790000000) signé, complet DIT absent"; VERTS=$((VERTS + 1))
    # parité (KE#94) : les tâches écrites en clair dans le vérificateur autonome == celles du paquet
    if python3 -B -c "import sys; sys.path[:0]=['$RACINE','$RACINE/outils']; import verifier_lot as v; from veilleur.battement import TACHES; sys.exit(0 if set(TACHES)==set(v.TACHES_INDEXEES) else 1)"; then
      echo "  [cadence] OK — parité TACHES du paquet == TACHES_INDEXEES du vérificateur"; VERTS=$((VERTS + 1))
    else echo "  [cadence] ÉCHEC — le vérificateur et le paquet ne connaissent pas les mêmes tâches"; ECHECS+=("cadence: parité"); ROUGES=$((ROUGES + 1)); fi
    # l index RE-SIGNÉ mais incohérent : REFUSÉ par le vérificateur, avec le bon motif
    for mode in empreinte present sans_index cardinal hors_index; do
      rm -rf "$M/lot-$mode" && cp -r "$M/lot" "$M/lot-$mode"
      python3 -B - "$M/lot-$mode" "$TRAVAIL/cadence/attest-b.hex" "$RACINE" "$mode" <<'PYEOF'
import hashlib, json, os, sys
lot, cle, racine, mode = sys.argv[1:5]
sys.path.insert(0, racine)
from veilleur.attest import AttestKey
from veilleur.verdict import canonical
m = json.load(open(os.path.join(lot, "MANIFESTE.json"), encoding="utf-8"))
if mode == "empreinte":
    m["battements"]["passe"]["sha256"] = "0" * 64
elif mode == "present":
    m["battements"]["differentiel-complet"]["présent"] = True
elif mode == "sans_index":
    del m["battements"]
elif mode == "cardinal":
    del m["battements"]["differentiel-complet"]
else:                                         # un battement épinglé que l index ne cite pas
    open(os.path.join(lot, "battement-intrus.json"), "w").write("{}")
    m["fichiers"]["battement-intrus.json"] = hashlib.sha256(b"{}").hexdigest()
k = AttestKey.load(cle); p = canonical(m); d = b"spindex-veilleur-b-lot/1\n"
s = json.load(open(os.path.join(lot, "SIGNATURE.json"), encoding="utf-8"))
s["signature"] = k.sign(d + p).hex(); s["empreinte_manifeste_sha256"] = hashlib.sha256(p).hexdigest()
json.dump(m, open(os.path.join(lot, "MANIFESTE.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
json.dump(s, open(os.path.join(lot, "SIGNATURE.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
PYEOF
      if ( cd "$M" && SPINDEX_B_INDEX_EXIGE_DEPUIS=0 python3 -B "$RACINE/outils/verifier_lot.py" --lot "lot-$mode" --clé-publique "$TRAVAIL/cadence/attest-b.pub" > "$M/verif-$mode.log" 2>&1 ); then
        echo "  [cadence] ÉCHEC — index incohérent ($mode) re-signé ACCEPTÉ"; ECHECS+=("cadence: index $mode"); ROUGES=$((ROUGES + 1))
      elif grep -qE "index des battements|SANS index" "$M/verif-$mode.log"; then
        echo "  [cadence] OK — index incohérent ($mode), signature valide : REFUSÉ par recoupement"; VERTS=$((VERTS + 1))
      else
        echo "  [cadence] ÉCHEC — refusé pour une autre raison ($mode) : $(head -1 "$M/verif-$mode.log")"; ECHECS+=("cadence: motif $mode"); ROUGES=$((ROUGES + 1))
      fi
    done
    # un lot ANTÉRIEUR sans index, seuil par défaut : accepté, et SIGNALÉ comme tel
    if ( cd "$M" && python3 -B "$RACINE/outils/verifier_lot.py" --lot lot-sans_index --clé-publique "$TRAVAIL/cadence/attest-b.pub" > "$M/verif-ancien.log" 2>&1 ) \
       && grep -qF "absent" "$M/verif-ancien.log"; then
      echo "  [cadence] OK — lot antérieur au seuil sans index : accepté et signalé"; VERTS=$((VERTS + 1))
    else echo "  [cadence] ÉCHEC — lot antérieur mal traité (voir $M/verif-ancien.log)"; ECHECS+=("cadence: antérieur"); ROUGES=$((ROUGES + 1)); fi
  else echo "  [cadence] ÉCHEC — lot à battements multiples non vérifiable"; ECHECS+=("cadence: signature"); ROUGES=$((ROUGES + 1)); fi
else
  echo "  [cadence] ÉCHEC — battements par tâche absents ou rafraîchis (voir $M/publier.log)"; ECHECS+=("cadence: battements"); ROUGES=$((ROUGES + 1))
fi
fi
echo
# Assertion de COUVERTURE (KE#111) : un filtre de jambes mal écrit ne ferait rien tourner du tout et
# le banc sortirait 0 en n ayant rien exercé.
if [ "$((VERTS + ROUGES))" -eq 0 ]; then
  echo "ARRET : aucun contrôle n a été exécuté (filtre « $JAMBES »). Un banc qui ne mesure rien ne passe pas." >&2
  exit 2
fi
echo "=== $VERTS contrôle(s) au vert, $ROUGES au rouge (jambes : $JAMBES) ==="
if [ "$ROUGES" -ne 0 ]; then
  printf '  - %s\n' "${ECHECS[@]}"
  exit 1
fi
echo "Le job échoue sur un contrôle rouge, refuse une chaîne inattendue, et passe quand tout va bien."
exit 0
