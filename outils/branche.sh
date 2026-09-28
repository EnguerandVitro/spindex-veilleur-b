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

# « la branche n'existe pas » et « je n'ai pas pu joindre le dépôt » ne doivent PAS se confondre : un
# fetch en échec lu comme « branche neuve » repartirait d'une branche orpheline et perdrait l'état
# (registre d'amorçage compris). `ls-remote --exit-code` rend 2 si et seulement si la branche est absente.
# Aucun identifiant requis : le dépôt est public (checkout en persist-credentials: false).
git ls-remote --exit-code --heads origin "$BRANCHE" >/dev/null 2>&1
LS=$?
if [ "$LS" != 0 ] && [ "$LS" != 2 ]; then
  echo "ARRET : dépôt distant injoignable (git ls-remote code $LS) — ni branche existante ni branche neuve prouvée." >&2
  exit 2
fi
if [ "$LS" = 0 ]; then
  git fetch origin "$BRANCHE" >/dev/null 2>&1 || { echo "ARRET : la branche $BRANCHE existe mais son fetch échoue." >&2; exit 2; }
  git worktree add "$DOSSIER" "origin/$BRANCHE" >/dev/null 2>&1 || exit 2
  ( cd "$DOSSIER" && git checkout -B "$BRANCHE" "origin/$BRANCHE" >/dev/null 2>&1 ) || exit 2
  echo "arbre $DOSSIER prêt sur « $BRANCHE » (branche existante, histoire conservée)"
else
  git worktree add --detach "$DOSSIER" >/dev/null 2>&1 || exit 2
  ( cd "$DOSSIER" && git checkout --orphan "$BRANCHE" >/dev/null 2>&1 && git rm -rqf . >/dev/null 2>&1 ) || true
  echo "arbre $DOSSIER prêt sur « $BRANCHE » (branche NEUVE, premier passage)"
fi
