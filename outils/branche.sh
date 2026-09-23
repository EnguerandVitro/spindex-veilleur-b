#!/usr/bin/env bash
# Préparer un arbre de travail git sur la branche de DONNÉES `attestations`, qu elle existe ou non.
#
# Pourquoi une branche plutôt qu un fichier : c est le seul canal qui sorte de GitHub Actions et qui
# soit lisible par la machine de surveillance avec un simple `git fetch`, SANS compte, SANS jeton, et
# SANS que quoi que ce soit ait le droit d écrire chez elle. Le SENS du transport est ce qui compte :
# la surveillance TIRE, l instance b ne pousse jamais vers la machine du keeper.
#
# La branche est APPEND-ONLY, jamais réécrite : c est ce qui permet de remonter le temps et de
# constater après coup qu un lot a été publié, ou qu il manque. Elle grossit donc, d environ vingt
# kilo-octets par passage. Voir README, « Entretien » : la remettre à plat est un geste HUMAIN, une
# fois par an, jamais une poussée en force automatique (elle effacerait l histoire que la branche
# existe précisément pour garder).
#
#   outils/branche.sh <branche> <dossier>
set -uo pipefail
BRANCHE="${1:?ARRET : nom de branche attendu}"
DOSSIER="${2:?ARRET : dossier attendu}"

git worktree remove --force "$DOSSIER" 2>/dev/null || true
rm -rf "$DOSSIER"

if git fetch origin "$BRANCHE" >/dev/null 2>&1; then
  git worktree add "$DOSSIER" "origin/$BRANCHE" >/dev/null 2>&1 || exit 2
  ( cd "$DOSSIER" && git checkout -B "$BRANCHE" "origin/$BRANCHE" >/dev/null 2>&1 ) || exit 2
  echo "arbre $DOSSIER prêt sur « $BRANCHE » (branche existante, histoire conservée)"
else
  git worktree add --detach "$DOSSIER" >/dev/null 2>&1 || exit 2
  ( cd "$DOSSIER" && git checkout --orphan "$BRANCHE" >/dev/null 2>&1 && git rm -rqf . >/dev/null 2>&1 ) || true
  echo "arbre $DOSSIER prêt sur « $BRANCHE » (branche NEUVE, premier passage)"
fi
