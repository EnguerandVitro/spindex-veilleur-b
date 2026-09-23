#!/usr/bin/env bash
# Les cassures synthétiques : chaque garde est-elle PORTANTE ?
#
# Un banc au vert ne prouve rien tant qu on n a pas vérifié qu il sait virer au rouge. Pour chaque
# garde annoncée, on casse VOLONTAIREMENT le code qui la tient, on rejoue la jambe de banc qui la
# vise, et on exige qu elle ÉCHOUE. Si elle reste verte, la garde est décorative : elle ne mesure pas
# ce qu elle prétend mesurer (KE#76, KE#129).
#
# Deux précautions, apprises à leurs dépens :
#   — la cassure MAXIMALE d abord (KE#106) : si le banc ne rougit pas quand tout est cassé, il ne
#     rougira jamais, et toutes les cassures suivantes seraient des faux positifs ;
#   — `python3 -B` partout et purge des `__pycache__` entre chaque essai (KE#117) : une édition de
#     même taille dans la même seconde réutilise le bytecode d origine, la cassure n est jamais
#     exécutée, et la garde est déclarée portante à tort.
#
# Restauration : sauvegarde AVANT, `trap` sur EXIT INT TERM HUP, et vérification APRÈS que l arbre
# est bien revenu à l identique, par empreinte (KE#122). Ce script modifie des fichiers versionnés :
# il ne se permet pas de les laisser à moitié cassés si on l interrompt.
#
#   banc/cassures.sh <dossier de travail> <fichier de clé de banc>
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRAVAIL="${1:?ARRET : dossier de travail attendu}"
CLE="${2:?ARRET : fichier de cle de banc attendu}"
SAUVE="$TRAVAIL/sauvegarde"
export PYTHONDONTWRITEBYTECODE=1

A_SAUVER=(outils/juger.py outils/sceau.py outils/preparer.py outils/executer.sh outils/verifier_lot.py)

empreinte_arbre() {
  ( cd "$RACINE" && for f in "${A_SAUVER[@]}"; do sha256sum "$f"; done | sha256sum | cut -d' ' -f1 )
}

mkdir -p "$SAUVE"
for f in "${A_SAUVER[@]}"; do
  mkdir -p "$SAUVE/$(dirname "$f")"
  cp "$RACINE/$f" "$SAUVE/$f"
done
AVANT="$(empreinte_arbre)"

restaurer() {
  for f in "${A_SAUVER[@]}"; do cp "$SAUVE/$f" "$RACINE/$f"; done
  find "$RACINE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
}
trap restaurer EXIT INT TERM HUP

PORTANTES=0
DECORATIVES=0
declare -a MORTES=()

# casser <nom> <jambes visées> <fichier> <python de substitution>
casser() {
  local nom="$1" jambes="$2" fichier="$3" edit="$4"
  restaurer
  python3 -B -c "$edit" "$RACINE/$fichier" || { echo "  [$nom] la cassure elle-même a échoué"; exit 2; }
  # preuve que la cassure a bien MODIFIÉ le fichier : sans elle, on mesurerait le code intact
  if cmp -s "$RACINE/$fichier" "$SAUVE/$fichier"; then
    echo "  [$nom] ARRET : la cassure n a rien changé dans $fichier — l essai ne prouverait rien."
    MORTES+=("$nom: cassure sans effet")
    DECORATIVES=$((DECORATIVES + 1))
    restaurer
    return
  fi
  find "$RACINE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  local code=0
  BANC_JAMBES="$jambes" bash "$RACINE/banc/preuves.sh" "$TRAVAIL" "$CLE" > "$TRAVAIL/cassure-$nom.log" 2>&1 || code=$?
  restaurer
  if [ "$code" -ne 0 ]; then
    echo "  [$nom] ROUGE — la garde est PORTANTE (jambes : $jambes)"
    PORTANTES=$((PORTANTES + 1))
  else
    echo "  [$nom] VERT — la garde est DÉCORATIVE : cassée, rien ne s en aperçoit (voir $TRAVAIL/cassure-$nom.log)"
    MORTES+=("$nom (jambes : $jambes)")
    DECORATIVES=$((DECORATIVES + 1))
  fi
}

echo "=== cassures synthétiques du veilleur b ==="
echo
echo "--- 0 : cassure MAXIMALE — si le banc ne rougit pas ici, il ne rougira nulle part"
casser maximale "temoin chaine controle sceau secret" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("    return {\n        \"format\": 1,", "    motifs = []\n    return {\n        \"format\": 1,")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 1 : le jugement ne voit plus un contrôle rouge (resultat == refus)"
casser controle_rouge "controle" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("        elif resultat == \"refus\":", "        elif resultat == \"CASSURE-jamais\":")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 2 : le jugement ne nomme plus la chaîne inattendue"
casser chaine_inattendue "chaine" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("if resultat == \"erreur\" and code == \"chaine_inattendue\":",
              "if resultat == \"erreur\" and code == \"CASSURE-jamais\":")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 3 : le jugement ne voit plus une tâche en erreur (la chaîne inattendue en est une)"
casser tache_en_erreur "chaine" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("if resultat == \"erreur\" and code == \"chaine_inattendue\":",
              "if False:")
s = s.replace("        elif resultat == \"erreur\":", "        elif False:")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 4 : le sceau de la copie accepte tout"
casser sceau "sceau" outils/sceau.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("def verifier():", "def verifier():\n    return {\"fichiers_verifies\": 0, \"croises_avec_le_scelle\": 0,\n            \"sources_executees\": 0, \"empreinte_sources\": None,\n            \"release\": None, \"scelle_le\": None}")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 5 : un secret absent est remplacé par une valeur bidon au lieu d un ARRET"
casser secret "secret" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("def _secret(nom):\n    v = os.environ.get(nom)",
              "def _secret(nom):\n    v = os.environ.get(nom) or (\"11\" * 32)")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 6 : le lot n est plus publié quand le jugement est ROUGE (le veilleur se tait)"
casser publication_malgre_rouge "chaine controle" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("echo \"--- 6/6 lot publié\"", "echo \"--- 6/6 lot publié\"\n[ \"$JUGE\" = \"0\" ] || exit \"$JUGE\"")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 7 : le témoin positif — le jugement est ROUGE quoi qu il arrive"
casser temoin_positif "temoin" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("        \"verdict\": \"ROUGE\" if motifs else \"VERT\",",
              "        \"verdict\": \"ROUGE\",")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 8 : le vérificateur de lot réimporte le paquet veilleur (il ne tournerait plus seul)"
casser verificateur_autonome "temoin autonome" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("def verifier(lot_dir, ancre):",
              "def verifier(lot_dir, ancre):\n    from veilleur.attest import verify as _inutile  # CASSURE")
open(p, "w", encoding="utf-8").write(s)
'

echo
echo "--- 9 : le vérificateur se rabat sur la clé que le lot transporte quand l ancre manque"
casser ancre_hors_du_lot "temoin autonome" outils/verifier_lot.py '
import sys, json
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = s.replace("def verifier(lot_dir, ancre):\n    attendue = charger_ancre(ancre)",
              "def verifier(lot_dir, ancre):\n    import json as _j, os as _o\n"
              "    if not ancre:\n"
              "        ancre = _j.load(open(_o.path.join(lot_dir, SIGNATURE), encoding=\"utf-8\"))[\"clé_publique\"]  # CASSURE\n"
              "    attendue = charger_ancre(ancre)")
open(p, "w", encoding="utf-8").write(s)
'

restaurer
APRES="$(empreinte_arbre)"
echo
echo "=== $PORTANTES garde(s) portante(s), $DECORATIVES décorative(s) ==="
echo "arbre avant $AVANT"
echo "arbre après $APRES"
if [ "$AVANT" != "$APRES" ]; then
  echo "ARRET : l arbre n est pas revenu à l identique après les cassures." >&2
  exit 2
fi
if [ "$DECORATIVES" -ne 0 ]; then
  printf '  garde décorative : %s\n' "${MORTES[@]}"
  exit 1
fi
if [ "$PORTANTES" -eq 0 ]; then    # KE#111 : zéro cassure exécutée passerait « sans faute »
  echo "ARRET : aucune cassure n a été exécutée." >&2
  exit 2
fi
echo "Chaque garde annoncée a été cassée et le banc l a vue."
exit 0
