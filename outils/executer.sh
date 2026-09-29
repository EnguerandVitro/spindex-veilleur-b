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
#   B_VECTEURS  (banc seulement) vecteurs de convention à la place de config/vecteurs-convention.json
#   B_BUDGET_S  (banc seulement) budget PLUS COURT que `budget_veiller_s` de la configuration (jamais plus long :
#               le paquet retient la plus proche des deux échéances)
set -uo pipefail
# Échéance d arrêt PROPRE des différentiels, comptée depuis MAINTENANT : l étape « Veiller » est tuée à 36 min,
# et un différentiel tué ne publie ni battement ni point de reprise. Lue plus bas, après validation de la
# configuration par preparer.py ; l horloge, elle, part d ici.
# À la NANOSECONDE (KE#164) : une restauration de `etat/` faite dans la même seconde que ce début aurait, avec
# `date +%s` et une comparaison `>=`, des mtime « postérieures » — un rapport d'hier passerait pour frais.
DEBUT="$(date +%s.%N)"

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
rm -f "$ETAT/ARRET.json"     # marqueur d'amorçage interrompu : jamais hérité d'une exécution précédente
rm -f "$ETAT/ETAPE.json"     # étape EN COURS (lue par la Barrière si « Veiller » est tué au délai)
rm -f "$ETAT/CACHE_CONTREDIT"   # marqueur « cache contredit NON écarté » : jamais hérité
rm -f "$ETAT/JUGEMENT.json"     # un jugement d'une exécution précédente ne doit pas être lu comme celui-ci
# L'instant de DÉBUT de cette exécution, ÉCRIT (jamais une mtime copiée : `cp -r` sans `-p` remet les mtime au
# moment de la restauration) : publier_etat.sh s'en sert pour savoir si un rapport `derniere-*.json` est d'ICI.
echo "$DEBUT" > "$ETAT/DEBUT"
# DEBUT doit être posé APRÈS toute restauration de `etat/` : sinon un fichier restauré aurait une mtime postérieure
# et un rapport d'hier redeviendrait « de cette exécution ». Vérifié ici, sur les fichiers déjà présents, AVANT que
# quoi que ce soit n'écrive dans `etat/` — un écart est un ARRÊT nommé, jamais un jugement faussé.
if ! python3 -B - "$ETAT/etat" "$DEBUT" <<'PYEOF'
import os, sys
racine, debut = sys.argv[1], float(sys.argv[2])
tard = [os.path.join(d, f) for d, _, fs in os.walk(racine) for f in fs
        if os.path.getmtime(os.path.join(d, f)) >= debut]
if tard:
    print(f"ARRÊT : {len(tard)} fichier(s) de etat/ restauré(s) APRÈS le DEBUT de cette exécution ({tard[0]}) : "
          f"la fraîcheur des rapports serait fausse (KE#164). Restaurer AVANT de lancer executer.sh.", file=sys.stderr)
    sys.exit(1)
PYEOF
then exit 2; fi
# KE#151 : écarter un cache CONTREDIT hors de `etat/`. Si ni le déplacement ni la suppression n'aboutissent, le
# cache est TOUJOURS là : on le DIT et on pose `CACHE_CONTREDIT`, qui interdit toute publication de `etat/`
# (etat_partiel.sh, étape « Publier ») — jamais un « SUPPRIMÉ » affiché sur un cache resté en place.
ecarter_cache() {   # <motif>
  local rej="$ETAT/journaux-rejete-$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$ETAT/etat/journaux" "$rej" 2>/dev/null || rm -rf "$ETAT/etat/journaux" 2>/dev/null
  if [ -d "$ETAT/etat/journaux" ]; then
    touch "$ETAT/CACHE_CONTREDIT"
    echo "::error title=veilleur b::cache de journaux CONTREDIT ($1) et IMPOSSIBLE à écarter : etat/journaux reste en place, la publication de etat/ est BLOQUÉE (CACHE_CONTREDIT)"
  elif [ -d "$rej" ]; then
    echo "::error title=veilleur b::cache de journaux CONTREDIT ($1) — écarté dans $rej, non publié ; relu depuis le déploiement au prochain job"
  else
    echo "::error title=veilleur b::cache de journaux CONTREDIT ($1) — déplacement impossible, SUPPRIMÉ ; relu depuis le déploiement au prochain job"
  fi
}
etape() { "${PY[@]}" -c 'import json,sys,time;json.dump({"étape":sys.argv[2],"début":time.strftime("%H:%M:%SZ",time.gmtime())},open(sys.argv[1],"w",encoding="utf-8"),ensure_ascii=False)' "$ETAT/ETAPE.json" "$1"; }

# ---------------------------------------------------------------- 1. la copie est-elle le code scellé
echo "--- 1/6 sceau de la copie"
"${PY[@]}" "$RACINE/outils/sceau.py" vérifier || exit 2

# ---------------------------------------------------------------- 1bis. la copie calcule-t-elle les feuilles DU CONTRAT ?
# Le sceau ne compare la copie qu a son propre FIGE.json : une copie périmée et son scellé périmé
# s accordent parfaitement (4 jours sans séparation de domaine, lot C-4). Ici la référence ne vient
# PAS de la copie : feuilles dorées calculées par cast depuis les étiquettes du contrat (KE#130/#137).
echo "--- 1bis/6 convention merkle conforme au contrat"
"${PY[@]}" "$RACINE/outils/conformite.py" vérifier --vecteurs "${B_VECTEURS:-$RACINE/config/vecteurs-convention.json}" || exit 2

# ---------------------------------------------------------------- 2. configuration et clé (jamais imprimées)
echo "--- 2/6 configuration"
"${PY[@]}" "$RACINE/outils/preparer.py" --config "$CONFIG" --etat "$ETAT" || exit 2
export SPINDEX_VEILLEUR_ENV="$ETAT/veilleur-b.env"
BUDGET="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["budget_veiller_s"])' "$CONFIG")" \
  || { echo "ARRÊT : budget_veiller_s illisible dans $CONFIG." >&2; exit 2; }
if [ -n "${B_BUDGET_S:-}" ] && [ "$B_BUDGET_S" -lt "$BUDGET" ]; then BUDGET="$B_BUDGET_S"; fi
ECHEANCE=$(( ${DEBUT%.*} + BUDGET ))
echo "    échéance d arrêt propre des différentiels : $(date -u -d "@$ECHEANCE" +%H:%M:%SZ) (budget $BUDGET s)"

# ---------------------------------------------------------------- 2bis. état d'un AUTRE déploiement ?
# Au redéploiement, `outils/maj_chaine.py` change la configuration (commit humain, prouvé sur la chaîne), mais
# l'état restauré depuis la branche porte le registre d'amorçage de l'ANCIEN contrat : la passe refuserait
# pour toujours. L'ancien état est ARCHIVÉ (jamais détruit ; il reste dans l'histoire de la branche) et le
# job ré-amorce. Ce n'est PAS déclenché par la chaîne : seule une configuration commitée le déclenche.
if [ -f "$ETAT/etat/amorcage.json" ]; then
  ANCIEN="$("${PY[@]}" - "$ETAT/etat/amorcage.json" "$CONFIG" <<'PYEOF'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8")); c = json.load(open(sys.argv[2], encoding="utf-8"))
cle = lambda d: (int(d["chain_id"]), str(d["rewards"]).lower(), int(d["deploy_block"]), str(d["tx_deploiement"]).lower())
print("" if cle(r) == cle(c) else str(r["rewards"]).lower())
PYEOF
)" || { echo "ARRÊT : registre d amorçage ou configuration illisible." >&2; exit 2; }
  if [ -n "$ANCIEN" ]; then
    ARCH="$ETAT/etat-archive-$ANCIEN-$(date -u +%Y%m%dT%H%M%SZ)"
    echo "--- 2bis/6 NOUVEAU DÉPLOIEMENT déclaré par la configuration : état de $ANCIEN archivé dans $ARCH"
    mv "$ETAT/etat" "$ARCH" && mkdir -p "$ETAT/etat"
  fi
fi

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
  etape "amorçage"
  TXD="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["tx_deploiement"])' "$CONFIG")"
  # Le rapport s'écrit HORS de `etat/` : `etat/` est publié tel quel, y compris après un échec.
  RAPPORT="$ETAT/amorcage-rapport.json"
  AM=0
  # la preuve D (différentiel complet) est SEGMENTÉE : sous l échéance, elle s arrête proprement (EN_COURS, 20) ;
  # l état partiel publié la fait REPRENDRE au premier segment non vérifié au job suivant
  ( cd "$RACINE" && "${PY[@]}" -m veilleur amorcer --instance b --tx-deploiement "$TXD" --échéance-ts "$ECHEANCE" ) \
    > "$RAPPORT" || AM=$?
  cat "$RAPPORT"            # données publiques : le journal du job doit les montrer
  if [ "$AM" != 0 ]; then
    # Un cache que la chaîne a CONTREDIT (D = DIVERGENT) ne doit pas survivre : publié comme état partiel,
    # chaque job suivant le reprendrait et refuserait POUR TOUJOURS. Il est écarté hors de `etat/`
    # (conservé pour examen, jamais publié) ; le job suivant relira depuis le déploiement.
    D_ETAT="$("${PY[@]}" -c 'import json,sys
try: print((json.load(open(sys.argv[1],encoding="utf-8")).get("preuves") or {}).get("D_différentiel_complet",{}).get("état",""))
except Exception: print("")' "$RAPPORT")"
    if [ "$D_ETAT" = "DIVERGENT" ] && [ -d "$ETAT/etat/journaux" ]; then
      ecarter_cache "amorçage : différentiel complet DIVERGENT"
    fi
    FIGE="$("${PY[@]}" -c 'import json,sys
try: s=json.load(open(sys.argv[1],encoding="utf-8"))["segments"]; print(s[-1]["à"] if s else "aucun")
except Exception: print("aucun")' "$ETAT/etat/journaux/curseur.json")"
    "${PY[@]}" -c 'import json,sys
json.dump({"étape":"amorçage","code":int(sys.argv[2]),"différentiel_D":sys.argv[3] or None,"journaux_figés_jusqu_à":sys.argv[4]},
          open(sys.argv[1],"w",encoding="utf-8"),ensure_ascii=False)' "$ETAT/ARRET.json" "$AM" "$D_ETAT" "$FIGE"
    echo "ARRÊT : amorçage refusé (code $AM, différentiel D : ${D_ETAT:-non atteint}, journaux figés jusqu au bloc $FIGE) — la chaîne de référence reste inconnue." >&2
    exit 2
  fi
else
  echo "--- 3/6 amorçage : registre présent, rien à faire"
fi

# ---------------------------------------------------------------- 5. la tâche elle-même
echo "--- 4/6 tâche « $TACHE »"
etape "tâche $TACHE"
CODE=0
if [ "$TACHE" = "passe" ]; then
  ( cd "$RACINE" && "${PY[@]}" -m veilleur passe --instance b --battement-dir "$ETAT/etat" ) || CODE=$?
else
  PORTEE="complète"
  [ "$TACHE" = "differentiel-quotidien" ] && PORTEE="quotidienne"
  ( cd "$RACINE" && "${PY[@]}" -m veilleur différentiel --instance b --portée "$PORTEE" \
      --battement-dir "$ETAT/etat" --échéance-ts "$ECHEANCE" ) || CODE=$?
  # KE#151, pour la TÂCHE comme pour l amorçage : un cache CONTREDIT par la chaîne (différentiel DIVERGENT)
  # ne doit pas être republié dans `etat/` — chaque job le reprendrait et refuserait pour toujours. Il est
  # écarté (conservé pour examen, jamais publié) ; la passe suivante re-fige depuis le déploiement. Les points
  # de reprise du différentiel restent : le contrôle (i) les invalide si le cache reconstruit diffère.
  # rapport écrit PAR CETTE exécution seulement (mtime STRICTEMENT > début, à la ns) : un DIVERGENT d hier ne doit pas faire écarter
  # le cache reconstruit depuis
  D_TACHE="$("${PY[@]}" -c 'import json,os,sys
try:
    p=sys.argv[1]; print(json.load(open(p,encoding="utf-8")).get("état","") if os.path.getmtime(p) > float(sys.argv[2]) else "")
except Exception: print("")' "$ETAT/etat/derniere-$TACHE.json" "$DEBUT")"
  if [ "$D_TACHE" = "DIVERGENT" ] && [ -d "$ETAT/etat/journaux" ]; then
    ecarter_cache "$TACHE DIVERGENT"
  fi
fi
echo "    code de sortie du paquet scellé : $CODE"
etape "jugement et lot"      # la tâche est allée au bout ; un arrêt plus loin est dit pour ce qu'il est

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
