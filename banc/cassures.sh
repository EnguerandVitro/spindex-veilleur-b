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

A_SAUVER=(outils/juger.py outils/sceau.py outils/preparer.py outils/executer.sh outils/verifier_lot.py outils/conformite.py outils/banc_fournisseur.py outils/pousser.sh outils/branche.sh outils/etat_partiel.sh outils/etat_sain.sh outils/publier.py)

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
s2 = s.replace("        \"verdict\": \"ROUGE\" if motifs else (\"EN_COURS\" if en_cours else \"VERT\"),",
               "        \"verdict\": \"ROUGE\",")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
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

echo
echo "--- 10 : conformité MAXIMALE — conformite.py rend 0 quoi qu il arrive"
casser conformite_maximale "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    a = ap.parse_args(argv)\n", "    a = ap.parse_args(argv)\n    return 0  # CASSURE\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 11 : la copie n est plus comparée aux feuilles dorées"
casser feuille_doree "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("elif calc != v[\"feuille\"]:", "elif False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 12 : la feuille SANS étiquette n est plus nommée comme la collision F03"
casser nom_F03 "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if calc == v[\"feuille_sans_etiquette\"]:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 13 : le fichier de vecteurs n est plus confronté à son générateur (KE#148)"
casser generateur "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if present != regenere:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 14 : l autorité amont n est plus recoupée avec la copie et la famille"
casser amont "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if len(set(emp.values())) != 1:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 15 : une copie périmée (FIGE.json ancien) n est plus vue (KE#137)"
casser fraicheur "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if fige_copie != fige_famille:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 16 : un domaine de paiement sans vecteur passe à vide (KE#111)"
casser couverture "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("vides = [d for d in DOMAINES_PAIEMENT if not compte.get(d)]", "vides = []")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 17 : des vecteurs d une AUTRE convention sont acceptés"
casser convention_des_vecteurs "conformite" outils/conformite.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if lue != annoncee:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 18 : le job ne vérifie plus la conformité avant de lire la chaîne"
casser job_conformite "conformite" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("\"${PY[@]}\" \"$RACINE/outils/conformite.py\" vérifier", "true")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 19 : preparer.py n écrit plus le profil des JOURNAUX dans le .env"
casser profil_ecrit "profil" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("(\"SPINDEX_RPC_PROFIL_JOURNAUX\", profil),", "")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 20 : une URL dRPC sans profil déclaré n est plus refusée"
casser profil_garde "profil" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if detectes and declare != detectes[0]:", "if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 21 : le faux dRPC accepte toute plage (le banc du profil ne mesurerait plus rien)"
casser faux_fidele "profil" outils/banc_fournisseur.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("ok = (b - a) <= SPAN_ACCEPTE - 1", "ok = True")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 22 : l état d un autre déploiement n est plus archivé au redéploiement"
casser redeploiement "redeploiement" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("mv \"$ETAT/etat\" \"$ARCH\" && mkdir -p \"$ETAT/etat\"", "true")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 23 : une poussée en échec redevient un step VERT muet (KE#105)"
casser poussee_muette "publication" outils/pousser.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("[ \"$POUSSE\" = oui ] ||", "true ||")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 24 : un origin injoignable redevient une branche NEUVE orpheline"
casser branche_injoignable "publication" outils/branche.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if [ \"$LS\" != 0 ] && [ \"$LS\" != 2 ]; then", "if false; then")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 25 : l état partiel d un amorçage interrompu n est plus sauvé (reprise du bloc de déploiement)"
casser etat_partiel "publication" outils/etat_partiel.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("cp -r \"$TRAVAIL/etat/.\" \"$PUB/etat/\"", "true")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 26 : un cache CONTREDIT par D n est plus écarté (il serait republié et refusé pour toujours)"
casser cache_contredit "cache_contredit" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("  mv \"$ETAT/etat/journaux\" \"$rej\" 2>/dev/null || rm -rf \"$ETAT/etat/journaux\" 2>/dev/null\n", "  true\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 27 : un état non inscriptible redevient un succès muet"
casser etat_non_inscriptible "publication" outils/etat_partiel.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("|| {\n  echo \"ARRET : copie de l état vers $PUB impossible\" >&2; exit 1; }", "|| true")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 28 : un fichier de type secret n empêche plus la publication"
casser etat_sain "publication" outils/etat_sain.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("  exit 1\nfi\nexit 0", "  exit 0\nfi\nexit 0")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 29 : la configuration déclare deux rôles, preparer.py n en écrit qu un (l état retombe sur dRPC)"
casser roles_separes "profil" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    if etat is not None:", "    if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 30 : le filet mesuré n est plus déclaré (silence retombe sur la période du cron)"
casser filet "cadence" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        if d.get(\"filet_s\") is not None or d.get(\"filet_source\"):", "        if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 31 : le lot ne porte plus que le battement de la tâche courante"
casser battements_par_tache "cadence" outils/publier.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        if nom in copies:", "        if nom in copies and nom == \"battement-passe.json\":")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 32 : le vérificateur ne recoupe plus l index des battements"
casser index_battements "cadence" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    index = man.get(\"battements\")\n    if index is None:", "    index = None\n    if index is None:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 33 : publier.py ne signe plus l index des battements (le vérificateur doit le refuser)"
casser index_publie "cadence" outils/publier.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        \"battements\": battements,", "")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 34 : un lot neuf SANS index est accepté"
casser index_exige "cadence" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        if not isinstance(produit, int) or produit >= INDEX_EXIGE_DEPUIS:", "        if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 35 : le cardinal de l index n est plus vérifié"
casser index_cardinal "cadence" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if not isinstance(index, dict) or set(index) != TACHES_INDEXEES:", "if not isinstance(index, dict) or not index:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 36 : un battement épinglé hors index passe"
casser index_sens_inverse "cadence" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        if hors_index:\n", "        if False:\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 35 : l échéance n est plus passée au différentiel (il serait TUÉ par le délai du job, sans point de reprise)"
casser echeance_tache "differentiels" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("--battement-dir \"$ETAT/etat\" --échéance-ts \"$ECHEANCE\" )", "--battement-dir \"$ETAT/etat\" )")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 36 : un cache CONTREDIT par un différentiel PLANIFIÉ n est plus écarté (KE#151)"
casser cache_contredit_tache "cache_contredit" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    ecarter_cache \"$TACHE DIVERGENT\"\n", "    true\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 37 : le budget n est plus écrit au .env (health publierait un pire cas qui croît avec l âge du contrat)"
casser budget_ecrit "cadence" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        if t in TACHES_SEGMENTEES_B:\n", "        if False:\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 38 : la période du TOUR complet n est plus écrite (le tour se referait à chaque déclenchement)"
casser tour_ecrit "cadence" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("            out.append((\"SPINDEX_VEILLEUR_TOUR_DIFFERENTIEL_COMPLET_S\", int(d[\"tour_s\"])))", "            pass")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 39 : un différentiel PARTIEL qui progresse redevient ROUGE (noierait un vrai rouge, KE#153)"
casser juger_en_cours "differentiels" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("        elif resultat == \"partiel\" and code == \"differentiel_partiel\":", "        elif False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 40 : un différentiel PARTIEL qui progresse devient VERT (jamais vert sans couverture complète, KE#111)"
casser juger_jamais_vert "differentiels" outils/juger.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("(\"EN_COURS\" if en_cours else \"VERT\")", "\"VERT\"")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 41 : la borne haute du budget redevient 36 min (échéance dure au-delà du kill de l étape)"
casser budget_borne "cadence" outils/preparer.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    haute = int(ETAPE_VEILLER_S - MARGE_DURE_S - MARGE_JUGEMENT_LOT_S)", "    haute = ETAPE_VEILLER_S - 1")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 42 : un cache contredit NON écartable ne pose plus le marqueur (il serait publié, KE#151)"
casser marqueur_cache_contredit "cache_contredit" outils/executer.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("    touch \"$ETAT/CACHE_CONTREDIT\"\n", "    true\n")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 43 : l état partiel se publie malgré le marqueur CACHE_CONTREDIT"
casser etat_partiel_marqueur "cache_contredit" outils/etat_partiel.sh '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("if [ -f \"$TRAVAIL/CACHE_CONTREDIT\" ]; then", "if false; then")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
'

echo
echo "--- 44 : un jugement VERT sur un battement partiel est accepté par le vérificateur"
casser vert_partiel "cadence" outils/verifier_lot.py '
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s2 = s.replace("            if bat.get(\"resultat\") == \"partiel\":", "            if False:")
assert s2 != s, "motif de cassure introuvable"
open(p, "w", encoding="utf-8").write(s2)
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
