#!/usr/bin/env bash
# REFUSER de publier un dossier d'état qui contient ce qui ressemble à un secret.
#
# La branche `attestations` est PUBLIQUE et append-only : un secret qui y entre n'en ressort plus. La clé
# d'attestation et le `.env` vivent à côté de `etat/` (dans le dossier de travail), jamais dedans — ce
# contrôle vérifie que ça reste vrai au moment exact où l'on publie, au lieu de le supposer.
#
#   outils/etat_sain.sh <dossier etat>      sortie 0 : sain ; 1 : ARRÊT, fichiers nommés (jamais leur contenu)
set -uo pipefail
D="${1:?ARRET : dossier etat attendu}"
[ -d "$D" ] || { echo "ARRET : $D n est pas un dossier" >&2; exit 1; }
MAUVAIS="$(find "$D" -type f \( -name '*.hex' -o -name '*.env' -o -name '*.env.*' -o -name 'attest-*' \
            -o -name '*.pem' -o -name '*.key' -o -name 'id_*' \) -printf '%P\n' | sort)"
if [ -n "$MAUVAIS" ]; then
  echo "::error title=veilleur b::publication REFUSÉE — fichier(s) de type secret dans l état : $(echo "$MAUVAIS" | tr '\n' ' ')" >&2
  exit 1
fi
exit 0
