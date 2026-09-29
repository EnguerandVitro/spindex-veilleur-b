#!/usr/bin/env bash
# Sauver l'état PARTIEL d'un amorçage interrompu sur la branche `attestations`, pour que le job suivant
# REPRENNE au dernier segment figé au lieu de repartir du bloc de déploiement.
#
# Pourquoi : un amorçage refusé (run 36469251579 : dRPC 408 au milieu de la relecture) ne produit aucun
# lot signé, et l'étape « Publier » s'arrêtait là — le cache des journaux, déjà figé segment par segment
# sur le runner, partait avec la machine virtuelle. Chaque job recommençait donc depuis le déploiement.
#
# Conséquence à connaître : TOUT ce qui est dans `etat/` survit désormais à un échec. Un cache que la
# chaîne a CONTREDIT (différentiel D `DIVERGENT`) doit donc être écarté AVANT d'arriver ici — c'est
# `executer.sh` qui le déplace hors de `etat/` ; sinon chaque job le reprendrait et refuserait pour toujours.
#
# Ce qui est publié n'est PAS un lot : pas de signature, pas de jugement, et le commit le dit. C'est un
# cache, jamais cru sur parole : chaque passe relit sur la chaîne le hash du dernier bloc figé, et
# l'amorçage le confronte au différentiel complet avant d'écrire son registre.
#
#   outils/etat_partiel.sh <dossier travail> <arbre attestations> [tâche]
# Sortie 0 : commit préparé (à pousser). 3 : rien à sauver. Toute autre : échec (le job doit échouer).
set -uo pipefail
TRAVAIL="${1:?ARRET : dossier de travail attendu}"
PUB="${2:?ARRET : arbre attestations attendu}"
ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TACHE="${3:-}"
if [ ! -f "$TRAVAIL/etat/journaux/curseur.json" ]; then
  echo "aucun segment figé dans $TRAVAIL/etat : rien à sauver"
  exit 3
fi
# garde du cache contredit (marqueur OU preuve locale, KE#104/#151) + copie : UN seul script, joué par le banc (K3)
bash "$ICI/publier_etat.sh" copier "$TRAVAIL" "$PUB" ${TACHE:+"$TACHE"} || exit 1
git -C "$PUB" add -A etat || exit 1
FIGE="$(python3 -B -c 'import json,sys;s=json.load(open(sys.argv[1],encoding="utf-8"))["segments"];print(s[-1]["à"] if s else "rien")' "$TRAVAIL/etat/journaux/curseur.json")" || exit 1
if git -C "$PUB" diff --cached --quiet; then
  echo "état partiel inchangé depuis la dernière publication : journaux figés jusqu'au bloc $FIGE"
else
  git -C "$PUB" commit -q -m "veilleur b — $(date -u +%Y%m%dT%H%M%SZ) — ÉTAT PARTIEL (aucun lot signé ; journaux figés jusqu'au bloc $FIGE)" \
    || { echo "ARRET : commit de l état partiel impossible" >&2; exit 1; }
  echo "état partiel prêt : journaux figés jusqu'au bloc $FIGE"
fi
