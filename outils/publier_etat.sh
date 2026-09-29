#!/usr/bin/env bash
# Publier `travail/etat/` sur l'arbre de la branche `attestations` — et REFUSER de le faire quand il porte un cache
# de journaux que la chaîne a CONTREDIT et qui n'a pas pu être écarté (KE#151 : sinon chaque job le reprendrait et
# refuserait pour toujours).
#
# Deux preuves INDÉPENDANTES, chacune suffisante pour refuser (KE#104 : l'échec d'écrire le marqueur ne doit pas
# faire échouer OUVERT) :
#   (1) le marqueur `travail/CACHE_CONTREDIT`, posé par executer.sh quand ni `mv` ni `rm` n'ont pu écarter le cache ;
#   (2) une preuve LOCALE, relue ici sans rien demander à executer.sh : `etat/journaux` est présent ET
#       — soit le rapport de la tâche dit `état: DIVERGENT` (ou son battement `differentiel_divergent`) et le
#         compteur du battement a AVANCÉ par rapport au
#         battement déjà publié (c'est donc celui de CETTE exécution, jamais un DIVERGENT d'hier) ;
#       — soit `travail/ARRET.json` dit que la preuve D de l'amorçage de CETTE exécution est DIVERGENTE.
#
#   outils/publier_etat.sh garde   <travail> <arbre attestations> [tâche]   # vérifie seulement
#   outils/publier_etat.sh copier  <travail> <arbre attestations> [tâche]   # vérifie, puis copie etat/
# Sortie 0 : fait. 1 : REFUS (rien copié) ou échec.
set -uo pipefail
MODE="${1:?ARRET : mode (garde|copier) attendu}"
TRAVAIL="${2:?ARRET : dossier de travail attendu}"
PUB="${3:?ARRET : arbre attestations attendu}"
TACHES="${4:-passe differentiel-quotidien differentiel-complet}"
ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

refus() {
  echo "::error title=veilleur b::publication de etat/ BLOQUÉE : $1 — cache de journaux CONTREDIT resté dans etat/ ; intervention humaine" >&2
  exit 1
}

[ -f "$TRAVAIL/CACHE_CONTREDIT" ] && refus "marqueur CACHE_CONTREDIT"
if [ -d "$TRAVAIL/etat/journaux" ]; then
  PREUVE="$(python3 -B - "$TRAVAIL" "$PUB" $TACHES <<'PYEOF'
import json, os, sys
travail, pub, taches = sys.argv[1], sys.argv[2], sys.argv[3:]
def lire(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return None
for t in taches:
    b = lire(os.path.join(travail, "etat", f"battement-{t}.json"))
    rp = os.path.join(travail, "etat", f"derniere-{t}.json")
    r = lire(rp) or {}
    # Le rapport n'est réécrit qu'en SUCCÈS, le compteur du battement avance à CHAQUE exécution : un rapport
    # DIVERGENT d'hier sous une exécution en panne n'est PAS une preuve (contre-revue, KE#105 — sinon faux refus et
    # battement de la vraie panne non publié). Frais = mtime STRICTEMENT > DEBUT (ns) écrit par executer.sh ; DEBUT illisible ⇒ tenu
    # pour frais (échec FERMÉ).
    try:
        debut = float(open(os.path.join(travail, "DEBUT"), encoding="utf-8").read().strip())
        debut_lisible = True
        r_frais = os.path.exists(rp) and os.path.getmtime(rp) > debut          # STRICT, à la ns (KE#164)
    except (OSError, ValueError):
        debut_lisible, r_frais = False, True
    # DEBUT lisible : un rapport FRAIS DIVERGENT suffit, seul (revue finale de b, P1) — le rapport est écrit AVANT le
    # battement et la mise à l'écart du cache ; « Veiller » tué entre les deux laisse un rapport frais, un compteur
    # non avancé et aucun marqueur : sans cette jambe, le cache contredit serait publié.
    if debut_lisible and r_frais and r.get("état") == "DIVERGENT":
        print(f"rapport « {t} » DIVERGENT écrit par CETTE exécution (postérieur au DEBUT)")
        sys.exit(0)
    # DEBUT illisible : repli sur le compteur du battement (avancé ⇒ de cette exécution).
    # l'ÉTAT du rapport (même autorité qu'executer.sh), le code seulement en OU : l'ordre de priorité des codes
    # (finalité violée > DIVERGENT, erreur de couverture) masquerait un code `differentiel_divergent` (revue, P1-1)
    if not b or not (b.get("code") == "differentiel_divergent" or (r_frais and r.get("état") == "DIVERGENT")):
        continue
    avant = lire(os.path.join(pub, "etat", f"battement-{t}.json")) or {}
    if int(b.get("passe") or 0) > int(avant.get("passe") or 0):
        print(f"battement « {t} » DIVERGENT de cette exécution (passe {b.get('passe')})")
        sys.exit(0)
a = lire(os.path.join(travail, "ARRET.json"))
if a and a.get("différentiel_D") == "DIVERGENT":
    print("amorçage de cette exécution : preuve D DIVERGENTE")
PYEOF
)" || refus "preuve locale illisible"
  [ -n "$PREUVE" ] && refus "preuve locale : $PREUVE"
fi
[ "$MODE" = "garde" ] && exit 0
[ "$MODE" = "copier" ] || { echo "ARRET : mode « $MODE » inconnu" >&2; exit 1; }

bash "$ICI/etat_sain.sh" "$TRAVAIL/etat" || exit 1
rm -rf "$PUB/etat" && mkdir -p "$PUB/etat" && cp -r "$TRAVAIL/etat/." "$PUB/etat/" || {
  echo "ARRET : copie de l état vers $PUB impossible" >&2; exit 1; }
# verrous et fichiers temporaires d'écriture atomique : sans valeur hors de la machine, jamais publiés
find "$PUB/etat" \( -name '*.verrou' -o -name '.verrou' -o -name '*.tmp' \) -type f -delete || exit 1
exit 0
