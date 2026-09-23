#!/usr/bin/env bash
# Remettre la copie à jour après un nouveau scellé de la famille `backend/veilleur`.
#
# À lancer SUR LA MACHINE QUI DÉTIENT LA FAMILLE (celle du keeper), par un humain, après une livraison.
# C est le seul fil qui relie les deux infrastructures, et il ne va que dans un sens : du code public
# vers le dépôt public. Aucune donnée, aucune clé, aucun état ne passe par là.
#
# La source est la RELEASE EN SERVICE, pas l arbre de travail : c est le code que l instance a exécute
# réellement, et c est ce qui doit tourner des deux côtés. Copier l arbre de travail ferait tourner
# `b` sur un code que personne n a scellé ni livré — et une divergence entre les deux instances se
# lirait alors comme un désaccord sur la chaîne, alors que ce serait un désaccord sur le code.
#
#   outils/resynchroniser.sh [chemin de la release]
#
# Après quoi, et dans cet ordre :
#   1. `banc/preuves.sh` et `banc/cassures.sh` doivent repasser
#   2. `git add -A && git commit` en NOMMANT la release
#   3. `git push`
#   4. prévenir le coordinateur : les deux instances doivent porter la MÊME empreinte de sources, et
#      la surveillance la compare.
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAUT="$HOME/.local/share/spindex-testnet/releases/veilleur/courant/backend/veilleur"
SRC="${1:-$DEFAUT}"

[ -d "$SRC" ] || { echo "ARRET : source introuvable ($SRC)" >&2; exit 2; }
[ -f "$SRC/FIGE.json" ] || { echo "ARRET : $SRC ne porte pas FIGE.json — ce n est pas une famille scellée." >&2; exit 2; }

AVANT="$(python3 -B -c "
import json,sys
try: print(json.load(open('$RACINE/SCEAU.json',encoding='utf-8'))['empreinte_sources_attendue'])
except Exception: print('(aucune)')")"

rm -rf "$RACINE/veilleur"
mkdir -p "$RACINE/veilleur/public"
cp "$SRC"/*.py "$RACINE/veilleur/"
cp "$SRC/FIGE.json" "$SRC/README.md" "$SRC/.env.exemple" "$RACINE/veilleur/"
cp "$SRC"/public/* "$RACINE/veilleur/public/"
LIV="$(dirname "$(dirname "$SRC")")/LIVRAISON.json"
[ -f "$LIV" ] && cp "$LIV" "$RACINE/veilleur/LIVRAISON.json"
chmod -R u+w "$RACINE/veilleur"

python3 -B "$RACINE/outils/sceau.py" fabriquer || exit 2
python3 -B "$RACINE/outils/sceau.py" vérifier  || exit 2

APRES="$(python3 -B -c "
import json;print(json.load(open('$RACINE/SCEAU.json',encoding='utf-8'))['empreinte_sources_attendue'])")"

echo
echo "empreinte des sources AVANT : $AVANT"
echo "empreinte des sources APRÈS : $APRES"
if [ "$AVANT" = "$APRES" ]; then
  echo "(inchangée : la release en service est celle que la copie portait déjà)"
else
  echo "CHANGÉE. Rejouer banc/preuves.sh ET banc/cassures.sh AVANT de committer."
fi
echo
echo "Vérification croisée, à faire à la main : l instance a publie cette même empreinte dans"
echo "  ~/.local/state/spindex-testnet/veilleur-a/health.json  (champ « empreinte »)"
python3 -B -c "
import json
try:
    h = json.load(open('$HOME/.local/state/spindex-testnet/veilleur-a/health.json', encoding='utf-8'))
    e = h.get('empreinte')
    print('  instance a publie :', e)
    print('  ACCORD' if e == '$APRES' else '  DÉSACCORD — les deux instances n exécuteraient pas le même code')
except Exception as exc:
    print('  (health.json de a illisible ici :', exc, ')')"
