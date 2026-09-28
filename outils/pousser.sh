#!/usr/bin/env bash
# Pousser le commit de la branche de DONNÉES `attestations`, et ÉCHOUER BRUYAMMENT si ce n'est pas fait.
#
# Pourquoi un script : c'était une boucle dans le workflow, `git push … && break` sous `set -e`. Un
# `&&` neutralise `set -e` : après trois refus la boucle se terminait normalement et le step restait
# VERT sans avoir rien publié — un veilleur muet qui se déclare en bonne santé (KE#105). Extrait ici,
# il est exercé tel quel par le banc (jambe J), au lieu d'être une copie à la main du workflow.
#
#   outils/pousser.sh <arbre de la branche attestations> <ce qui est publié, ex. « lot » ou « état partiel »>
# Sortie 0 : poussé. Sortie 1 : NON publié après les essais (le job doit échouer).
set -uo pipefail
D="${1:?ARRET : arbre de travail attendu}"
QUOI="${2:?ARRET : nature de la publication attendue (lot, état partiel) — le message doit dire ce qui est publié}"
ESSAIS="${B_ESSAIS_POUSSEE:-3}"
ATTENTE="${B_ATTENTE_POUSSEE_S:-5}"
cd "$D" || exit 1
POUSSE=non
for essai in $(seq 1 "$ESSAIS"); do
  if git push origin HEAD:attestations; then POUSSE=oui; break; fi
  echo "poussée refusée (essai $essai/$ESSAIS) — je récupère et je recommence"
  if git fetch origin attestations; then
    git rebase origin/attestations || git rebase --abort || true
  fi
  sleep "$ATTENTE"
done
[ "$POUSSE" = oui ] || { echo "::error title=veilleur b::$QUOI NON publié sur attestations après $ESSAIS essais"; exit 1; }
echo "$QUOI publié sur attestations"
