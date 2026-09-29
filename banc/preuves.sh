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
#   N  différentiels       job TUÉ en plein différentiel après ≥ 2 points de reprise : le job suivant REPREND au
#                          premier segment non vérifié et rend VERT, couverture EXACTE ; budget épuisé -> ROUGE
#                          (jamais VERT sans couverture complète), lot publié quand même
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
JAMBES="${BANC_JAMBES:-temoin chaine controle sceau secret autonome conformite profil redeploiement publication cache_contredit fuite cadence differentiels}"
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
# le DERNIER segment figé qui PORTE un journal : depuis que la chaîne dépasse 200 000 blocs, le cache en a
# plusieurs, et le dernier peut être vide (constaté le 2026-09-29 : la jambe falsifiait un segment vide, son
# assertion échouait, et le job tournait sur un cache INTACT — rouge pour une raison hors sujet, KE#142)
for m in reversed(cur["segments"]):
    p = os.path.join(d, m["fichier"]); seg = json.load(open(p, encoding="utf-8"))
    if seg["journaux"]:
        break
assert seg["journaux"], "aucun segment figé ne porte de journal : rien à falsifier"
seg["journaux"] = seg["journaux"][:-1]                      # un journal RETIRÉ du cache
json.dump(seg, open(p, "w", encoding="utf-8"), ensure_ascii=False)
m["n"] = len(seg["journaux"]); m["sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()   # sha RECALCULÉ
json.dump(cur, open(os.path.join(d, "curseur.json"), "w", encoding="utf-8"), ensure_ascii=False)
PYEOF
[ $? = 0 ] || { echo "ARRET : la falsification du cache (jambe K) a échoué : la jambe ne mesurerait rien" >&2; exit 2; }
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
# K2 — la TÂCHE (différentiel planifié), pas seulement l amorçage : un cache contredit est écarté de `etat/`
K2="$TRAVAIL/cache_contredit_tache"; rm -rf "$K2" && mkdir -p "$K2"
cp -r "$TRAVAIL/reference/etat" "$K2/etat"
rm -f "$K2/etat/differentiel-quotidien.json" "$K2"/etat/*.verrou
python3 -B - "$K2/etat/journaux" <<'PYEOF'
import hashlib, json, os, sys
d = sys.argv[1]; cur = json.load(open(os.path.join(d, "curseur.json"), encoding="utf-8"))
for m in cur["segments"]:                                   # le PREMIER segment qui porte un journal
    p = os.path.join(d, m["fichier"]); seg = json.load(open(p, encoding="utf-8"))
    if seg["journaux"]:
        break
assert seg["journaux"], "aucun journal figé : rien à falsifier"
seg["journaux"] = seg["journaux"][:-1]
json.dump(seg, open(p, "w", encoding="utf-8"), ensure_ascii=False)
m["n"] = len(seg["journaux"]); m["sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()
json.dump(cur, open(os.path.join(d, "curseur.json"), "w", encoding="utf-8"), ensure_ascii=False)
PYEOF
[ $? = 0 ] || { echo "ARRET : la falsification du cache (jambe K2) a échoué : la jambe ne mesurerait rien" >&2; exit 2; }
rm -rf "$TRAVAIL/k3-source" && cp -r "$K2/etat" "$TRAVAIL/k3-source"      # le MÊME état falsifié, pour K3
code=0
B_ETAT="$K2" B_LOT="$K2/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" SPINDEX_B_RPC_URL="$RPC_VRAI" \
SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" bash "$RACINE/outils/executer.sh" > "$K2.log" 2>&1 || code=$?
if [ "$code" = 1 ] && [ ! -d "$K2/etat/journaux" ] && ls -d "$K2"/journaux-rejete-* >/dev/null 2>&1 \
   && [ -f "$K2/lot/SIGNATURE.json" ] && python3 -B -c 'import json,sys
j=json.load(open(sys.argv[1],encoding="utf-8"));sys.exit(0 if j["verdict"]=="ROUGE" and j["battement"]["code"]=="differentiel_divergent" else 1)' "$K2/lot/JUGEMENT.json"; then
  echo "  [cache_contredit] OK — différentiel quotidien DIVERGENT : ROUGE, lot publié, journaux écartés hors de etat/"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — tâche DIVERGENTE mal traitée (code $code, voir $K2.log)"; ECHECS+=("cache_contredit: tâche"); ROUGES=$((ROUGES + 1))
fi
# K3 — le cache contredit ne PEUT PAS être écarté (mv et rm refusés sur etat/journaux) : il reste en place, le
# marqueur CACHE_CONTREDIT est posé et AUCUNE publication de etat/ n'a lieu (KE#151) — jamais « SUPPRIMÉ » affiché
K3="$TRAVAIL/cache_contredit_bloque"; rm -rf "$K3" && mkdir -p "$K3/shim"
cp -r "$TRAVAIL/k3-source" "$K3/etat"
for outil in mv rm; do
  printf '#!/bin/bash\nfor a in "$@"; do case "$a" in */etat/journaux) echo "shim : %s refusé sur $a" >&2; exit 1;; esac; done\nexec %s "$@"\n' \
    "$outil" "$(command -v "$outil")" > "$K3/shim/$outil"
  chmod +x "$K3/shim/$outil"
done
code=0
PATH="$K3/shim:$PATH" B_ETAT="$K3" B_LOT="$K3/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" \
SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" bash "$RACINE/outils/executer.sh" > "$K3.log" 2>&1 || code=$?
ep=0; bash "$RACINE/outils/etat_partiel.sh" "$K3" "$K3/pub" differentiel-quotidien > "$K3.ep.log" 2>&1 || ep=$?
if [ -f "$K3/CACHE_CONTREDIT" ] && [ -d "$K3/etat/journaux" ] && [ "$ep" = 1 ] && [ ! -d "$K3/pub/etat/journaux" ] \
   && grep -q "IMPOSSIBLE à écarter" "$K3.log" && ! grep -q "SUPPRIMÉ" "$K3.log"; then
  echo "  [cache_contredit] OK — cache contredit non écartable : CACHE_CONTREDIT posé, publication de etat/ REFUSÉE (1)"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — cache contredit non écartable mal traité (code $code, etat_partiel $ep, voir $K3.log)"
  ECHECS+=("cache_contredit: non écartable"); ROUGES=$((ROUGES + 1))
fi
# K3b — MÊME situation, et le marqueur lui-même ne peut pas être écrit (touch refusé) : la PREUVE LOCALE (battement
# DIVERGENT de cette exécution + etat/journaux présent) refuse seule — jamais un échec ouvert (KE#104)
K3B="$TRAVAIL/cache_contredit_sans_marqueur"; rm -rf "$K3B" && mkdir -p "$K3B/shim"
cp -r "$TRAVAIL/k3-source" "$K3B/etat"; cp "$K3/shim/mv" "$K3/shim/rm" "$K3B/shim/"
printf '#!/bin/bash\nfor a in "$@"; do case "$a" in */CACHE_CONTREDIT) echo "shim : touch refusé" >&2; exit 1;; esac; done\nexec %s "$@"\n' \
  "$(command -v touch)" > "$K3B/shim/touch"; chmod +x "$K3B/shim/touch"
mkdir -p "$K3B/pub/etat" && cp "$TRAVAIL/k3-source/battement-differentiel-quotidien.json" "$K3B/pub/etat/" 2>/dev/null
PATH="$K3B/shim:$PATH" B_ETAT="$K3B" B_LOT="$K3B/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" \
SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" bash "$RACINE/outils/executer.sh" > "$K3B.log" 2>&1
g=0; bash "$RACINE/outils/publier_etat.sh" copier "$K3B" "$K3B/pub" differentiel-quotidien > "$K3B.pub.log" 2>&1 || g=$?
if [ ! -f "$K3B/CACHE_CONTREDIT" ] && [ -d "$K3B/etat/journaux" ] && [ "$g" = 1 ] && [ ! -d "$K3B/pub/etat/journaux" ] \
   && grep -q "preuve locale" "$K3B.pub.log"; then
  echo "  [cache_contredit] OK — marqueur NON écrit : la preuve locale refuse seule la publication (KE#104)"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — sans marqueur, publication de etat/ non refusée (garde $g, voir $K3B.pub.log)"
  ECHECS+=("cache_contredit: preuve locale"); ROUGES=$((ROUGES + 1))
fi
# K3e/K3f/K3g — la preuve locale, jambe par jambe, SANS marqueur, sur des états fabriqués (état sain + fichiers) :
#   K3e : rapport DIVERGENT mais battement codé `differentiel_finalite_violee` (la finalité prime) ⇒ refus (ÉTAT lu)
#   K3f : battement DIVERGENT d'HIER restauré à l'identique du publié ⇒ PUBLIÉ (jamais un refus éternel)
#   K3g : ARRET.json de l'amorçage, preuve D DIVERGENTE ⇒ refus
#   K3h : rapport DIVERGENT d'HIER (antérieur au DEBUT écrit), tâche en panne ce coup-ci ⇒ PUBLIÉ (pas de faux refus)
#   K3i : même chose, rapport postérieur au DEBUT ⇒ refus
#   K3l : rapport FRAIS DIVERGENT, battement NON avancé (tué entre les deux), pas de marqueur ⇒ refus
for cas in K3e K3f K3g K3h K3i K3l; do
  D="$TRAVAIL/cache_$cas"; rm -rf "$D" && mkdir -p "$D/pub/etat"; cp -r "$TRAVAIL/reference/etat" "$D/etat"
  python3 -B - "$D" "$cas" <<'PYEOF'
import json, os, sys
d, cas = sys.argv[1], sys.argv[2]
b = {"format": 1, "service": "veilleur", "instance": "b", "tache": "differentiel-quotidien", "ts": 1, "passe": 5,
     "bloc": 1, "resultat": "refus", "code": "differentiel_divergent", "detail": "banc"}
if cas == "K3e":
    b.update({"passe": 6, "code": "differentiel_finalite_violee"})
    json.dump({"état": "DIVERGENT"}, open(os.path.join(d, "etat", "derniere-differentiel-quotidien.json"), "w"))
    json.dump(dict(b, passe=5), open(os.path.join(d, "pub", "etat", "battement-differentiel-quotidien.json"), "w"))
elif cas == "K3f":
    json.dump({"état": "DIVERGENT"}, open(os.path.join(d, "etat", "derniere-differentiel-quotidien.json"), "w"))
    json.dump(b, open(os.path.join(d, "pub", "etat", "battement-differentiel-quotidien.json"), "w"))
elif cas == "K3l":
    # « Veiller » tué entre le rapport et le battement : rapport FRAIS DIVERGENT, battement NON avancé, pas de marqueur
    json.dump({"état": "DIVERGENT"}, open(os.path.join(d, "etat", "derniere-differentiel-quotidien.json"), "w"))
    json.dump(b, open(os.path.join(d, "pub", "etat", "battement-differentiel-quotidien.json"), "w"))
    import time
    open(os.path.join(d, "DEBUT"), "w").write(str(time.time() - 10))
elif cas in ("K3h", "K3i"):
    # rapport DIVERGENT puis exécution de cette tâche en PANNE (`rpc_error`, compteur avancé) : le rapport n'est
    # d'ICI que s'il est postérieur au DEBUT écrit (K3i) ; d'hier (K3h) il ne prouve rien ⇒ publié
    json.dump({"état": "DIVERGENT"}, open(os.path.join(d, "etat", "derniere-differentiel-quotidien.json"), "w"))
    b.update({"passe": 6, "resultat": "erreur", "code": "rpc_error"})
    json.dump(dict(b, passe=5), open(os.path.join(d, "pub", "etat", "battement-differentiel-quotidien.json"), "w"))
    import time
    maintenant = int(time.time())
    open(os.path.join(d, "DEBUT"), "w").write(str(maintenant + 10 if cas == "K3h" else maintenant - 10))
else:
    json.dump({"étape": "amorçage", "code": 2, "différentiel_D": "DIVERGENT", "journaux_figés_jusqu_à": "1"},
              open(os.path.join(d, "ARRET.json"), "w"), ensure_ascii=False)
    b = None
if b is not None:
    json.dump(b, open(os.path.join(d, "etat", "battement-differentiel-quotidien.json"), "w"))
PYEOF
  g=0; bash "$RACINE/outils/publier_etat.sh" copier "$D" "$D/pub" differentiel-quotidien > "$D.log" 2>&1 || g=$?
  if { [ "$cas" != K3f ] && [ "$cas" != K3h ] && [ "$g" = 1 ] && grep -q "preuve locale" "$D.log" && [ ! -d "$D/pub/etat/journaux" ]; } \
     || { { [ "$cas" = K3f ] || [ "$cas" = K3h ]; } && [ "$g" = 0 ] && [ -f "$D/pub/etat/journaux/curseur.json" ]; }; then
    echo "  [cache_contredit] OK — $cas : garde $g comme attendu"; VERTS=$((VERTS + 1))
  else
    echo "  [cache_contredit] ÉCHEC — $cas : garde $g (voir $D.log)"; ECHECS+=("cache_contredit: $cas"); ROUGES=$((ROUGES + 1))
  fi
done
# K3j (KE#164) — restauration RÉELLE de etat/ (cp -r) et executer.sh lancé dans la MÊME seconde, tâche en panne
# (chaîne inattendue) : le rapport DIVERGENT d'hier, restauré, ne doit PAS passer pour frais ⇒ etat/ PUBLIÉ
D="$TRAVAIL/cache_K3j"; rm -rf "$D" "$D.src" && mkdir -p "$D/pub/etat" && cp -r "$TRAVAIL/reference/etat" "$D.src"
python3 -B - "$D.src" "$D/pub/etat" <<'PYEOF'
import json, os, sys
src, pub = sys.argv[1], sys.argv[2]
b = {"format": 1, "service": "veilleur", "instance": "b", "tache": "differentiel-quotidien", "ts": 1, "passe": 5,
     "bloc": 1, "resultat": "refus", "code": "differentiel_divergent", "detail": "banc"}
json.dump({"état": "DIVERGENT"}, open(os.path.join(src, "derniere-differentiel-quotidien.json"), "w"))
json.dump(b, open(os.path.join(src, "battement-differentiel-quotidien.json"), "w"))
json.dump(b, open(os.path.join(pub, "battement-differentiel-quotidien.json"), "w"))
PYEOF
python3 -B -c 'import time; time.sleep(1.02 - time.time() % 1)'     # début d une seconde : cp et DEBUT dans la même
cp -r "$D.src" "$D/etat"
B_ETAT="$D" B_LOT="$D/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" SPINDEX_B_RPC_URL="$RPC_AUTRE" \
SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" bash "$RACINE/outils/executer.sh" > "$D.exec.log" 2>&1
g=0; bash "$RACINE/outils/publier_etat.sh" copier "$D" "$D/pub" differentiel-quotidien > "$D.log" 2>&1 || g=$?
if [ "$g" = 0 ] && [ -f "$D/pub/etat/journaux/curseur.json" ] && python3 -B -c 'import json,sys
b=json.load(open(sys.argv[1]));sys.exit(0 if b["passe"]==6 and b["code"]=="chaine_inattendue" else 1)' "$D/etat/battement-differentiel-quotidien.json"; then
  echo "  [cache_contredit] OK — K3j : restauration et DEBUT dans la même seconde, rapport d hier NON frais ⇒ publié"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — K3j : garde $g (voir $D.log, $D.exec.log)"; ECHECS+=("cache_contredit: K3j"); ROUGES=$((ROUGES + 1))
fi
# K3k — restauration APRÈS le DEBUT (un fichier de etat/ plus récent que le début) : executer.sh s'ARRÊTE, nommé
D="$TRAVAIL/cache_K3k"; rm -rf "$D" && mkdir -p "$D" && cp -r "$TRAVAIL/reference/etat" "$D/etat"
touch -d "@$(( $(date +%s) + 30 ))" "$D/etat/amorcage.json"
code=0
B_ETAT="$D" B_LOT="$D/lot" B_TACHE=passe B_CONFIG="$CONFIG_BANC" SPINDEX_B_RPC_URL="$RPC_VRAI" \
SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" bash "$RACINE/outils/executer.sh" > "$D.log" 2>&1 || code=$?
if [ "$code" = 2 ] && grep -q "APRÈS le DEBUT" "$D.log"; then
  echo "  [cache_contredit] OK — K3k : restauration postérieure au DEBUT ⇒ ARRÊT (2) nommé"; VERTS=$((VERTS + 1))
else
  echo "  [cache_contredit] ÉCHEC — K3k : code $code (voir $D.log)"; ECHECS+=("cache_contredit: K3k"); ROUGES=$((ROUGES + 1))
fi
# K3c — le marqueur SEUL (état sain, aucune preuve locale) suffit à refuser ; K3d — témoin positif : état sain, pas de
# marqueur ⇒ publié, cache compris (sans lui, une garde qui refuse TOUT passerait les jambes ci-dessus)
for cas in K3c K3d; do
  D="$TRAVAIL/cache_$cas"; rm -rf "$D" && mkdir -p "$D/pub"; cp -r "$TRAVAIL/reference/etat" "$D/etat"
  [ "$cas" = K3c ] && touch "$D/CACHE_CONTREDIT"
  g=0; bash "$RACINE/outils/publier_etat.sh" copier "$D" "$D/pub" passe > "$D.log" 2>&1 || g=$?
  if { [ "$cas" = K3c ] && [ "$g" = 1 ] && [ ! -d "$D/pub/etat" -o ! -d "$D/pub/etat/journaux" ] && grep -q "marqueur" "$D.log"; } \
     || { [ "$cas" = K3d ] && [ "$g" = 0 ] && [ -f "$D/pub/etat/journaux/curseur.json" ]; }; then
    echo "  [cache_contredit] OK — $cas : garde $g comme attendu"; VERTS=$((VERTS + 1))
  else
    echo "  [cache_contredit] ÉCHEC — $cas : garde $g (voir $D.log)"; ECHECS+=("cache_contredit: $cas"); ROUGES=$((ROUGES + 1))
  fi
done
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
      and c["planifiée"] is True and c["période_attendue_s"] == 21600 and c["tour_s"] == 604800
      and q["budget_s"] == c["budget_s"] == 1740 and p["budget_s"] is None
      # le budget BORNE le pire cas publié (sinon il croîtrait avec l'âge du contrat) : silence fini et dérivé
      and c["silence_max_s"] is not None and c["silence_max_s"] <= 21600 + 600 + 1740 + 378 + 21600)
print(p["période_attendue_s"], p["silence_max_s"], q["période_s"], c["planifiée"], c.get("période_attendue_s"),
      c.get("tour_s"), c.get("budget_s"), c.get("silence_max_s"))
sys.exit(0 if ok else 1)
PYEOF
then echo "  [cadence] OK — passe 900 s / silence ≥ 32 400 s (filet mesuré) ; quotidien 86 400 s ; complet 21 600 s, tour 604 800 s, budget 1 740 s"; VERTS=$((VERTS + 1))
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
    # un lot ANTÉRIEUR au seuil de l'index, daté comme tel : le banc ne doit pas dépendre de l'heure à laquelle il
    # tourne (constaté le 2026-09-29 après 06:00Z : le lot « antérieur » fabriqué à l'instant ne l'était plus)
    m["produit_le_ts"] = 1790661600 - 3600
    m["produit_le"] = "2026-09-29T05:00:00Z"
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
    # jugement VERT alors que le battement indexé de la tâche jugée dit `partiel` (re-signé) : REFUSÉ, motif nommé
    rm -rf "$M/lot-vert-partiel" && cp -r "$M/lot" "$M/lot-vert-partiel"
    python3 -B - "$M/lot-vert-partiel" "$TRAVAIL/cadence/attest-b.hex" "$RACINE" <<'PYEOF'
import hashlib, json, os, sys
lot, cle, racine = sys.argv[1:4]
sys.path.insert(0, racine)
from veilleur.attest import AttestKey
from veilleur.verdict import canonical
m = json.load(open(os.path.join(lot, "MANIFESTE.json"), encoding="utf-8"))
t = m["jugement"]["tache"]; f = f"battement-{t}.json"
b = json.load(open(os.path.join(lot, f), encoding="utf-8"))
b.update({"resultat": "partiel", "code": "differentiel_partiel",
          "couverture": {"bloc_debut": 1, "bloc_fin_cible": 9, "bloc_fin_verifie": 4, "segments_verifies": 0,
                         "segments_total": 1, "complet": False, "motif_partiel": "banc"}})
open(os.path.join(lot, f), "w", encoding="utf-8").write(json.dumps(b, ensure_ascii=False))
h = hashlib.sha256(open(os.path.join(lot, f), "rb").read()).hexdigest()
m["fichiers"][f] = h; m["battements"][t]["sha256"] = h; m["jugement"]["verdict"] = "VERT"
k = AttestKey.load(cle); p = canonical(m); d = b"spindex-veilleur-b-lot/1\n"
s = json.load(open(os.path.join(lot, "SIGNATURE.json"), encoding="utf-8"))
s["signature"] = k.sign(d + p).hex(); s["empreinte_manifeste_sha256"] = hashlib.sha256(p).hexdigest()
json.dump(m, open(os.path.join(lot, "MANIFESTE.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
json.dump(s, open(os.path.join(lot, "SIGNATURE.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
PYEOF
    if ( cd "$M" && python3 -B "$RACINE/outils/verifier_lot.py" --lot lot-vert-partiel --clé-publique "$TRAVAIL/cadence/attest-b.pub" > "$M/verif-vert-partiel.log" 2>&1 ); then
      echo "  [cadence] ÉCHEC — jugement VERT sur un battement partiel ACCEPTÉ"; ECHECS+=("cadence: vert partiel"); ROUGES=$((ROUGES + 1))
    elif grep -q "contradiction" "$M/verif-vert-partiel.log"; then
      echo "  [cadence] OK — jugement VERT sur un battement partiel : REFUSÉ (contradiction nommée)"; VERTS=$((VERTS + 1))
    else echo "  [cadence] ÉCHEC — vert partiel refusé pour une autre raison : $(head -1 "$M/verif-vert-partiel.log")"; ECHECS+=("cadence: vert partiel motif"); ROUGES=$((ROUGES + 1)); fi
    # budget au-delà de la borne (échéance dure > kill de l'étape moins la marge du lot) : ARRÊT nommant la clé
    python3 -B -c 'import json,sys;c=json.load(open(sys.argv[1],encoding="utf-8"));c["budget_veiller_s"]=1741;json.dump(c,open(sys.argv[2],"w",encoding="utf-8"))' "$CONFIG_BANC" "$M/config-1741.json"
    mkdir -p "$M/prep"
    if SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" python3 -B "$RACINE/outils/preparer.py" \
         --config "$M/config-1741.json" --etat "$M/prep" > "$M/prep.log" 2>&1; then
      echo "  [cadence] ÉCHEC — budget 1 741 s accepté"; ECHECS+=("cadence: budget"); ROUGES=$((ROUGES + 1))
    elif grep -q "budget_veiller_s" "$M/prep.log"; then
      echo "  [cadence] OK — budget 1 741 s REFUSÉ, clé nommée (borne 2 160 − 120 − 300)"; VERTS=$((VERTS + 1))
    else echo "  [cadence] ÉCHEC — budget refusé sans nommer la clé : $(tail -1 "$M/prep.log")"; ECHECS+=("cadence: budget motif"); ROUGES=$((ROUGES + 1)); fi
  else echo "  [cadence] ÉCHEC — lot à battements multiples non vérifiable"; ECHECS+=("cadence: signature"); ROUGES=$((ROUGES + 1)); fi
else
  echo "  [cadence] ÉCHEC — battements par tâche absents ou rafraîchis (voir $M/publier.log)"; ECHECS+=("cadence: battements"); ROUGES=$((ROUGES + 1))
fi
fi
if voulue differentiels; then
echo
echo "--- N : différentiels REPRENABLES — job TUÉ en plein différentiel, reprise exacte au job suivant ; budget épuisé -> ROUGE"
etat_de_reference
N="$TRAVAIL/diff"; rm -rf "$N" && mkdir -p "$N"
cp -r "$TRAVAIL/reference/etat" "$N/etat"
# aucun point de reprise hérité : le quotidien vérifie depuis le déploiement (sans adopter le tour de l amorçage)
rm -f "$N/etat/differentiel-quotidien.json" "$N/etat/differentiel-complet.json" "$N"/etat/*.verrou
PTS="$N/etat/differentiel-quotidien.json"
points() { python3 -B -c 'import json,sys
try: print(len(json.load(open(sys.argv[1],encoding="utf-8"))["points"]))
except Exception: print(0)' "$PTS"; }
B_ETAT="$N" B_LOT="$N/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" \
SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  setsid bash "$RACINE/outils/executer.sh" > "$N/job1.log" 2>&1 &
PID=$!
# attente d une PROGRESSION positive, bornée, jamais d une absence (KE#131)
for _ in $(seq 1 360); do [ "$(points)" -ge 2 ] && break; sleep 0.5; done
kill -9 -- "-$PID" 2>/dev/null; wait "$PID" 2>/dev/null
K="$(points)"
if [ "$K" -ge 2 ] && ! grep -q "6/6 lot publié" "$N/job1.log"; then
  echo "  [differentiels] OK — job 1 tué après $K point(s) de reprise durables"; VERTS=$((VERTS + 1))
  FIN_K="$(python3 -B -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["points"][-1]["à"])' "$PTS")"
  code=0
  B_ETAT="$N" B_LOT="$N/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" \
  SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
    bash "$RACINE/outils/executer.sh" > "$N/job2.log" 2>&1 || code=$?
  if [ "$code" = 0 ] && python3 -B - "$N/etat/derniere-differentiel-quotidien.json" "$N/etat/battement-differentiel-quotidien.json" "$FIN_K" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8")); b = json.load(open(sys.argv[2], encoding="utf-8"))
fin_k = int(sys.argv[3]); c = b["couverture"]; seg = r["segments_cette_exécution"]
e = b["couverture_estimation"]
ok = (r["état"] == "IDENTIQUE" and b["resultat"] == "ok" and seg and seg[0]["de"] == fin_k + 1
      and c["complet"] is True and c["bloc_fin_verifie"] == c["bloc_fin_cible"]
      and c["segments_verifies"] == c["segments_total"] and e["journaux_couverts"] >= 1)
print("reprise au bloc", seg[0]["de"] if seg else None, "après", fin_k, "; couverture", c["bloc_fin_verifie"], "/",
      c["bloc_fin_cible"], "; journaux", e["journaux_couverts"])
sys.exit(0 if ok else 1)
PYEOF
  then echo "  [differentiels] OK — job 2 REPREND au premier segment non vérifié, couverture EXACTE, VERT"; VERTS=$((VERTS + 1))
  else echo "  [differentiels] ÉCHEC — reprise incorrecte (code $code, voir $N/job2.log)"; ECHECS+=("differentiels: reprise"); ROUGES=$((ROUGES + 1)); fi
else
  echo "  [differentiels] ÉCHEC — le job n a écrit que $K point(s) avant la borne d attente (voir $N/job1.log)"
  ECHECS+=("differentiels: aucune progression"); ROUGES=$((ROUGES + 1))
fi
# budget épuisé dès le départ : rien vérifié -> ERREUR nommée, ROUGE, lot publié (jamais un vert muet)
N0="$TRAVAIL/diff0"; rm -rf "$N0" && mkdir -p "$N0"
cp -r "$TRAVAIL/reference/etat" "$N0/etat"
rm -f "$N0/etat/differentiel-quotidien.json" "$N0/etat/differentiel-complet.json" "$N0"/etat/*.verrou
code=0
B_ETAT="$N0" B_LOT="$N0/lot" B_TACHE=differentiel-quotidien B_CONFIG="$CONFIG_BANC" B_BUDGET_S=0 \
SPINDEX_B_RPC_URL="$RPC_VRAI" SPINDEX_B_ATTEST_KEY_HEX="$(cat "$CLE")" \
  bash "$RACINE/outils/executer.sh" > "$N0.log" 2>&1 || code=$?
if [ "$code" = 1 ] && [ -f "$N0/lot/SIGNATURE.json" ] && python3 -B - "$N0/lot/JUGEMENT.json" <<'PYEOF'
import json, sys
j = json.load(open(sys.argv[1], encoding="utf-8")); b = j["battement"]
ok = (j["verdict"] == "ROUGE" and (b["resultat"], b["code"]) == ("partiel", "differentiel_sans_progression")
      and b["couverture"]["segments_verifies"] == 0 and b["couverture"]["complet"] is False
      and b["couverture_estimation"]["segments_restants"] > 0)
sys.exit(0 if ok else 1)
PYEOF
then echo "  [differentiels] OK — budget épuisé : ROUGE differentiel_sans_progression, lot signé publié"; VERTS=$((VERTS + 1))
else echo "  [differentiels] ÉCHEC — budget épuisé mal jugé (code $code, voir $N0.log)"; ECHECS+=("differentiels: budget"); ROUGES=$((ROUGES + 1)); fi
# le JUGEMENT d un différentiel partiel : EN_COURS s il progresse (jamais VERT, jamais ROUGE), ROUGE s il ne résorbe
# pas son retard. Battements fabriqués au format du paquet, empreinte du sceau : seule la jambe juger est exercée.
NJ="$TRAVAIL/diff-juger"
for cas in "differentiel_partiel EN_COURS 0" "differentiel_retard_non_resorbe ROUGE 1"; do
  set -- $cas
  rm -rf "$NJ" && mkdir -p "$NJ"
  python3 -B - "$NJ/battement-differentiel-complet.json" "$1" "$RACINE/SCEAU.json" <<'PYEOF'
import json, sys, time
e = json.load(open(sys.argv[3], encoding="utf-8"))["empreinte_sources_attendue"]
json.dump({"format": 1, "service": "veilleur", "instance": "b", "tache": "differentiel-complet", "ts": int(time.time()),
           "passe": 2, "bloc": 1, "resultat": "partiel", "code": sys.argv[2], "detail": "PARTIEL : banc",
           "couverture": {"bloc_debut": 1, "bloc_fin_cible": 9, "bloc_fin_verifie": 4, "segments_verifies": 0,
                          "segments_total": 1, "complet": False, "motif_partiel": "banc"},
           "empreinte": e, "rpc": {}, "fournisseurs": None}, open(sys.argv[1], "w", encoding="utf-8"))
PYEOF
  jc=0
  python3 -B "$RACINE/outils/juger.py" --etat "$NJ" --tache differentiel-complet --sortie 0 --sceau "$RACINE/SCEAU.json" \
    --precedent 1 --jugement "$NJ/J.json" > "$NJ.log" 2>&1 || jc=$?
  v="$(python3 -B -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["verdict"])' "$NJ/J.json" 2>/dev/null)"
  if [ "$v" = "$2" ] && [ "$jc" = "$3" ]; then
    echo "  [differentiels] OK — jugement de « $1 » : $v (sortie $jc)"; VERTS=$((VERTS + 1))
  else
    echo "  [differentiels] ÉCHEC — jugement de « $1 » : $v (sortie $jc), attendu $2 ($3)"; ECHECS+=("differentiels: juger $1"); ROUGES=$((ROUGES + 1))
  fi
done
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
