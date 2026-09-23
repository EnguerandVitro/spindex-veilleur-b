#!/usr/bin/env bash
# Les étapes de travail de l'instance b, DANS L'ORDRE. Un seul script, appelé par deux appelants :
# le workflow GitHub Actions, et le banc local. Ce n'est donc pas « le banc reproduit le job » —
# c'est le MÊME code des deux côtés, ce qui est la seule façon d'avoir une preuve locale qui
# vaille (un banc qui réécrit les étapes ne prouve rien du job réel).
#
# Ce que le workflow fait AUTOUR de ce script, et que ce script ne fait pas : récupérer le dépôt,
# restaurer l'état depuis la branche, installer les dépendances, publier l'artefact, pousser la
# branche. Tout ce qui LIT LA CHAÎNE et DÉCIDE est ici.
#
# Codes de sortie :
#   0  VERT   — la tâche a fait son travail, aucun contrôle rouge
#   1  ROUGE  — contrôle rouge, chaîne inattendue, tâche en erreur (le lot est quand même publié)
#   2  ARRÊT  — le montage lui-même n'est pas en état (sceau, secrets, configuration) : rien n'a été lu
#
# Variables attendues (aucune valeur par défaut pour les secrets) :
#   B_ETAT   dossier de travail        B_CONFIG  fichier de chaîne        B_TACHE  passe|differentiel-*
#   B_LOT    dossier du lot publié     SPINDEX_B_RPC_URL  SPINDEX_B_ATTEST_KEY_HEX
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pas d apostrophe dans ce message : bash ouvre une citation sur le ' contenu dans ${VAR:?mot}.
ETAT="${B_ETAT:?ARRET : B_ETAT (dossier de travail) doit etre pose}"
CONFIG="${B_CONFIG:-$RACINE/config/chaine-46630.json}"
TACHE="${B_TACHE:-passe}"
LOT="${B_LOT:-$ETAT/lot}"
# `-B` partout, et jamais de bytecode : une cassure synthétique de MÊME TAILLE dans la MÊME seconde
# réutiliserait le bytecode d'origine et ne serait jamais exécutée (KE#117).
export PYTHONDONTWRITEBYTECODE=1
PY=(python3 -B)

echo "::: veilleur b — tâche « $TACHE »"
mkdir -p "$ETAT/etat"

# ---------------------------------------------------------------- 1. la copie est-elle le code scellé
echo "--- 1/6 sceau de la copie"
"${PY[@]}" "$RACINE/outils/sceau.py" vérifier || exit 2

# ---------------------------------------------------------------- 2. configuration et clé (jamais imprimées)
echo "--- 2/6 configuration"
"${PY[@]}" "$RACINE/outils/preparer.py" --config "$CONFIG" --etat "$ETAT" || exit 2
export SPINDEX_VEILLEUR_ENV="$ETAT/veilleur-b.env"

# ---------------------------------------------------------------- 3. compteur AVANT (jambe de progression)
# Lu avant de lancer quoi que ce soit : c'est la valeur restaurée depuis la branche. Le jugement exige
# ensuite que le compteur ait AUGMENTÉ — une attente satisfaite par l'inaction n'est pas une attente
# (KE#131).
PRECEDENT="$("${PY[@]}" "$RACINE/outils/compteur.py" "$ETAT/etat/battement-$TACHE.json")"
echo "    compteur de passe avant exécution : $PRECEDENT"

# ---------------------------------------------------------------- 4. amorçage si le registre manque
# `amorcer` est en LECTURE SEULE et idempotent. Sans registre, une passe ne lit rien et rend
# `amorcage_absent` : ce n'est pas « aucun défaut constaté », c'est « je ne peux pas prouver que je
# regarde la bonne chaîne ». Le registre vit dans la branche `attestations` ; s'il a été perdu, on le
# reconstruit ici depuis la chaîne, ce qui est long mais correct.
if [ ! -f "$ETAT/etat/amorcage.json" ]; then
  echo "--- 3/6 amorçage (registre absent : reconstruction depuis la chaîne)"
  TXD="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["tx_deploiement"])' "$CONFIG")"
  ( cd "$RACINE" && "${PY[@]}" -m veilleur amorcer --instance b --tx-deploiement "$TXD" ) \
    || { echo "ARRÊT : amorçage refusé — la chaîne de référence reste inconnue." >&2; exit 2; }
else
  echo "--- 3/6 amorçage : registre présent, rien à faire"
fi

# ---------------------------------------------------------------- 5. la tâche elle-même
echo "--- 4/6 tâche « $TACHE »"
CODE=0
if [ "$TACHE" = "passe" ]; then
  ( cd "$RACINE" && "${PY[@]}" -m veilleur passe --instance b --battement-dir "$ETAT/etat" ) || CODE=$?
else
  PORTEE="complète"
  [ "$TACHE" = "differentiel-quotidien" ] && PORTEE="quotidienne"
  ( cd "$RACINE" && "${PY[@]}" -m veilleur différentiel --instance b --portée "$PORTEE" \
      --battement-dir "$ETAT/etat" ) || CODE=$?
fi
echo "    code de sortie du paquet scellé : $CODE"

# ---------------------------------------------------------------- 6. jugement, puis lot (même si ROUGE)
echo "--- 5/6 jugement"
# Le jugement s ecrit HORS du lot : `publier.py` refait le dossier du lot de zero (un lot doit contenir
# ce qu il annonce et rien d autre), ce qui effacerait un jugement ecrit dedans avant lui.
JUGE=0
"${PY[@]}" "$RACINE/outils/juger.py" --etat "$ETAT/etat" --tache "$TACHE" --sortie "$CODE" \
  --sceau "$RACINE/SCEAU.json" --precedent "$PRECEDENT" --jugement "$ETAT/JUGEMENT.json" || JUGE=$?

echo "--- 6/6 lot publié"
# Publié AVANT de sortir en erreur : un veilleur qui se tait quand il trouve quelque chose serait pire
# qu'un veilleur absent.
"${PY[@]}" "$RACINE/outils/publier.py" --etat "$ETAT/etat" --lot "$LOT" --cle "$ETAT/attest-b.hex" \
  --sceau "$RACINE/SCEAU.json" --jugement "$ETAT/JUGEMENT.json" --config "$CONFIG" || exit 2

# Témoin de bout en bout : le lot qu'on vient de signer doit passer le vérificateur, avec l'ancre
# posée hors du lot. S'il ne passe pas, ce qu'on publie n'est pas vérifiable et il vaut mieux le
# savoir ici que chez le lecteur (KE#119 : on ne suppose pas qu'un vérificateur dirait oui).
"${PY[@]}" "$RACINE/outils/verifier_lot.py" --lot "$LOT" --clé-publique "$ETAT/attest-b.pub" >/dev/null \
  || { echo "ARRÊT : le lot que je viens de signer ne passe pas son propre vérificateur." >&2; exit 2; }

exit "$JUGE"
