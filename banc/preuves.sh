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
JAMBES="${BANC_JAMBES:-temoin chaine controle sceau secret autonome}"
voulue() { [[ " $JAMBES " == *" $1 "* ]]; }

export PYTHONDONTWRITEBYTECODE=1
find "$RACINE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

VERTS=0
ROUGES=0
declare -a ECHECS=()

etat_de_reference() {   # un état déjà amorcé, pour ne pas relire toute la chaîne à chaque jambe
  if [ ! -f "$TRAVAIL/reference/etat/amorcage.json" ]; then
    echo "  (amorçage de référence : lecture complète de la chaîne, une seule fois)"
    mkdir -p "$TRAVAIL/reference"
    B_ETAT="$TRAVAIL/reference" B_LOT="$TRAVAIL/reference/lot" B_TACHE=passe \
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
jambe temoin 0 "$RACINE/config/chaine-46630.json" "$RPC_VRAI" "$(cat "$CLE")"
fi

if voulue chaine; then
echo
echo "--- A : le secret RPC pointe une AUTRE chaîne (4663) — refus bruyant attendu"
jambe chaine 1 "$RACINE/config/chaine-46630.json" "$RPC_AUTRE" "$(cat "$CLE")" lot
motif_present chaine chaine_inattendue
fi

if voulue controle; then
echo
echo "--- B : contrôle ROUGE (fenêtre d état sous le besoin de sûreté) — le job doit échouer"
fi
python3 -B - "$RACINE/config/chaine-46630.json" "$TRAVAIL/config-besoin-haut.json" <<'PYEOF'
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
jambe sceau 2 "$RACINE/config/chaine-46630.json" "$RPC_VRAI" "$(cat "$CLE")"
cp "$TRAVAIL/merkle.py.sauve" "$RACINE/veilleur/merkle.py"
python3 -B "$RACINE/outils/sceau.py" vérifier >/dev/null \
  && echo "  [sceau] OK — la copie est restaurée à l identique" \
  || { echo "  [sceau] ÉCHEC — la copie n a PAS été restaurée"; ECHECS+=("sceau: restauration"); ROUGES=$((ROUGES+1)); }
fi

if voulue secret; then
echo
echo "--- E : la clé d attestation n est pas fournie"
jambe secret 2 "$RACINE/config/chaine-46630.json" "$RPC_VRAI" ""
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
