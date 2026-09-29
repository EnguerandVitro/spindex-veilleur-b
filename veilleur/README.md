---
title: SPINDEX — le veilleur
date: 2026-09-21
atelier: veilleur
territoire: backend/veilleur/, backend/rapports/veilleur.md
---

# Le veilleur

Composant de **sécurité**, en **lecture seule**. Il tient la garantie de `rewards/REWARDS_SPEC.md`
§21 — celle qu'aucun code de contrat ne porte. `postWeek` et `openDraw` acceptent une racine merkle
**arbitraire** ; la borne réelle est hors chaîne. Sans ce composant, le pouvoir du Safe sur les
dotations et les enveloppes n'est borné par personne.

## Ce qu'il fait

Avant chaque `postWeek` et chaque `openDraw`, il rend un **feu vert horodaté et signé** — ou un refus
motivé — portant la **racine exacte** que le Safe s'apprête à signer.

| Verdict | Sortie | Sens |
|---|---|---|
| `GO` | 0 | j'ai vérifié, tout est vrai, voici la racine couverte |
| `REFUS` | 10 | j'ai vérifié, c'est FAUX — motifs nommés |
| `INDISPONIBLE` | 20 | je n'ai PAS pu vérifier |

Aucun autre chemin ne rend 0. « Rien à signaler » et « je n'ai pas pu vérifier » sont impossibles à
confondre : c'est la raison d'être du troisième état.

**Le veilleur ne bloque rien techniquement.** Il n'a aucune clé de chaîne. « Bloquer la publication »
signifie exactement ceci : *le Safe s'interdit de signer sans un feu vert portant cette racine*.
C'est une règle de quorum humaine, et la présenter autrement serait un mensonge. Quand le veilleur
est en panne, le Safe s'abstient et la semaine glisse — **et le glissement doit alerter**, sinon on
aura remplacé une panne bruyante par une semaine qui disparaît en silence.

## Les trois contrôles qui portent la garantie

`OD-F` (exhaustivité), `OD-G` (égalité des poids) et **`OD-J` (somme des stakes == `totalStaked()`
relu on-chain)**. Les autres — racine, pavage, dotation détenue — sont **tous satisfaits** par une
table de poids à une seule feuille au nom du keeper, qui vole 100 % de la dotation (revue adverse,
P0-1). Ne jamais les affaiblir ; ils portent le drapeau `porte_la_garantie` dans chaque verdict, et
le banc exige qu'ils soient les motifs du refus sur la table exacte de chaque attaque.

**Pourquoi OD-J a dû être ajouté (audit rouge externe, 2026-09-23, P0-2).** OD-F et OD-G tirent leur
ensemble de référence — la reconstruction — du flux de journaux que le veilleur a lui-même lu ou
figé : c'est le SUJET, pas l'autorité (KE#130). Une adresse absente **à la fois** de la
reconstruction et de la table n'était comptée nulle part, et le verdict était **GO** sur une table
qui ampute un staker réel. Deux entrées y mènent — un nœud RPC qui omet un `Staked` au moment du
figeage, un cache local empoisonné — et aucune n'était visible.

`totalStaked()` est le seul agrégat que la chaîne tient elle-même sur cet ensemble **inénumérable**
(`_locks` est un mapping privé : ni `stakerCount()`, ni `stakerAt(i)`). OD-J le relit au bloc
d'instantané et lui confronte **deux sommes de sources indépendantes**, en **ÉGALITÉ EXACTE** :

| jambe | source | ce qu'elle survit à |
|---|---|---|
| (1) | `Σ stakeOf` relus un par un au bloc d'instantané | un cache local empoisonné (elle ne lit aucun cache) |
| (2) | `Σ amount` rejoués depuis les journaux | un nœud qui ment sur `stakeOf` (elle ne lit aucun état) |

Une **inégalité** serait satisfaite par la panne du côté sous test (KE#121) ; une somme tirée de la
table serait le sujet confronté à lui-même (KE#127). Un `totalStaked()` illisible rend OD-J
**INDISPONIBLE**, jamais OK — et donc jamais un feu vert (KE#105).

## `vérifier` : l'ancre de confiance est HORS de l'enveloppe

```bash
python3 -B -m veilleur vérifier <verdict.json> --clé-publique <hex|fichier>
```

La signature était vérifiée contre `signature["clé_publique"]`, **la clé que porte l'enveloppe
qu'on vérifie** : n'importe qui fabriquait un document, le signait avec SA clé, et obtenait
`signature_valide: true` et un code de sortie **0**. L'outil que le signataire du Safe exécute
n'authentifiait personne — la garantie annoncée ne tenait pas.

La clé publique **attendue** est désormais obligatoire : `--clé-publique` (64 caractères
hexadécimaux, ou le chemin d'un fichier d'ancrage), ou `SPINDEX_ATTEST_PUBKEY_FILE` dans `.env`.
Absente des deux côtés, la commande **REFUSE** — elle ne se rabat jamais sur la clé du document.
Une enveloppe signée par une autre clé lève `CleInattendue`, imprime les deux clés et sort **2**.
`verify_envelope(env, *, clé_publique_attendue)` a un paramètre **nommé et obligatoire** (KE#62) :
la forme d'appel héritée lève `TypeError` au lieu de s'auto-attester.

La sortie porte aussi le **contexte lié** — `chainId`, adresse `rewards`, bloc et hash
d'instantané — pour qu'un verdict d'un autre déploiement ne puisse pas être présenté ici sans que
personne ne le voie.

## Reproductible par n'importe qui — c'est ce qui empêche le piège J+90

La règle « le Safe s'abstient tant que le veilleur n'a pas donné son feu vert », combinée à une panne
DURABLE du veilleur, mène au **balayage J+90** : la règle de sécurité produirait elle-même le dommage
qu'elle doit empêcher. La réponse n'est pas de l'assouplir, c'est que **n'importe qui puisse refaire
la vérification** — elle ne porte que sur des données publiques.

```bash
python3 -B -m veilleur vérifier-publiquement --table <fichier|url> [--rpc <url>]
```

Ce chemin ne lit **aucun `.env`**, n'utilise **aucune clé**, ne touche **pas** à `contracts/` et n'a
**aucune dépendance** (Keccak-256 embarqué en Python pur). Tout ce dont il a besoin est dans
`veilleur/public/`, un lot dont chaque fichier est épinglé par `sha256`. Le verdict rendu est
**NON SIGNÉ** — un tiers ne signe pas à notre place — et porte une `empreinte_reproductible` qui doit
égaler la nôtre. `bench/test_public.py` l'exécute depuis un dossier vierge, environnement vidé et
dépendances rendues inimportables, et exige la même empreinte.

Deux portées : **`table seule`** (sans RPC — racine, pavage, totaux, doublons ; rejouable pour
toujours, **ne vaut jamais feu vert**) et **`complète`** (avec RPC, dans la fenêtre d'état).

## La convention merkle est LUE, jamais recopiée — et le lot publié doit être à jour

`convention.py` est le **seul** lecteur de la convention merkle et des étiquettes de domaine
(`TAG_CLAIM`, `TAG_DRAW`, `TAG_SEASON`) ; il les prend dans `rewards_constants.json` et **recalcule**
chaque étiquette depuis la préimage citée avant de la croire. `merkle.py` et `chainabi.py` la lui
demandent. Aucune autre copie n'est tolérée : `bench/test_convention_domaine.py` balaie le paquet et
rougit si le texte de la convention réapparaît ailleurs.

**Conséquence d'exploitation.** `merkle.py` **refuse de se charger** contre des artefacts dont la
convention a bougé. Un lot publié fabriqué avant la séparation de domaine (§12.1) n'en porte aucune
étiquette : le veilleur s'arrête en le disant, et en nommant le remède. Le lot embarqué
(`veilleur/public/`) doit donc être refait à chaque changement du contrat :

```bash
python3 -B -m veilleur.outils.faire_lot_public          # exige contracts/out à jour
```

`faire_lot_public` refuse de fabriquer un lot dont l'ABI n'a pas été compilée sur la source
présente ; si elle refuse, c'est `contracts/out` qu'il faut régénérer, pas le lot.

Pourquoi ce soin : sans étiquette, la feuille de paiement `claim` et la feuille de classement de
saison de l'indexeur sont **le même mot** — mêmes types ABI, même double keccak. Mesuré :
`0x2d935f84…` pour les deux. Une feuille de saison, publiée en clair par l'indexeur, était donc
directement encaissable dans l'arbre `claim`.

## Le compte à rebours J+90 / J+30

```bash
python3 -B -m veilleur compte-à-rebours
```

Alerte de **premier rang**, rendue à chaque passage pour chaque échéance ouverte, **quel que soit
l'état du reste**. Le dommage ne vient pas d'une anomalie mais du temps qui passe pendant que tout va
bien : une alerte qui attend un seuil d'anomalie ne le verrait jamais. La gravité se **dérive** des
jours restants et finit en P0.

## Commandes

```bash
cd ~/stockslot/backend
python3 -B -m veilleur auditer-env                       # la règle de citation du .env (KE#107)
python3 -B -m veilleur clé-générer                       # n'imprime QUE la clé publique
python3 -B -m veilleur fenêtre                           # fenêtre d'état = MIN de 3 sondes, jugée contre le besoin (480 s)
python3 -B -m veilleur surveiller                        # absences, burn, racines, fenêtre
python3 -B -m veilleur avant-postweek --week 12
python3 -B -m veilleur avant-opendraw --week 12
python3 -B -m veilleur confirmer --bloc <n> --hash 0x…   # après que `finalized` a dépassé l'instantané
python3 -B -m veilleur vérifier etat/verdicts/….json     # vérification par un tiers
```

## Exploitation (instances `a` et `b`)

```bash
python3 -B -m veilleur passe --instance a --battement-dir <dossier>          # timer, toutes les 5 min
python3 -B -m veilleur différentiel --instance a --portée quotidienne       # timer, chaque jour
python3 -B -m veilleur différentiel --instance a --portée complète          # timer, chaque semaine
python3 -B -m veilleur différentiel --instance b --portée complète --échéance-ts <epoch>   # job borné (b)
python3 -B -m veilleur surveiller --depuis-zéro                             # reconstruction complète, à la main
```

- **Lecture incrémentale** (`journaux.py`) : journaux figés jusqu'à `finalized` seulement, par segments
  immuables ; le hash du dernier bloc figé est **relu sur la chaîne à chaque passe** (divergence : on
  recule et on le dit). La reconstruction **complète** reste la référence (vérificateur public).
- **Différentiels REPRENABLES par segments** (`segments.py`, 2026-09-29) : grille FIXE de 20 200 blocs ancrée
  au déploiement ; un point de reprise durable par segment vérifié (bornes, hash du bloc de fin lu chez le
  fournisseur de RÉFÉRENCE, empreinte et cardinal) ; l'exécution suivante reprend au premier segment non
  vérifié. Un segment vérifié n'est jamais relu SAUF invalidation, toujours EN AVAL : contenu du cache changé
  (0 appel) ou hash de borne qui ne concorde plus (réorganisation, chaîne rejouée, KE#132). Un segment
  CONTREDIT n'est jamais inscrit (KE#151). QUOTIDIEN = campagne permanente, seul le neuf est lu (adopte les
  points du tour complet) ; COMPLET = un TOUR depuis le déploiement tous les `tour_s`, sur autant
  d'exécutions qu'il faut ; entre deux tours, le tour terminé est ÉTENDU au neuf (après les contrôles). Budget : `--échéance-ts` et/ou
  `SPINDEX_VEILLEUR_BUDGET_DIFFERENTIEL_{QUOTIDIEN,COMPLET}_S` (facultatif ; absent = aucune limite, cas de `a`) :
  arrêt PROPRE avant chaque segment (estimation = max des 10 dernières durées, plafonnée au prior mesuré
  quand l'exécution n'a encore rien vérifié : une durée aberrante n'affame jamais les suivantes) ; échéance
  DURE (+120 s) posée sur le CLIENT RPC : délai de chaque appel réduit à ce qui reste, aucune relance ni attente
  au-delà (appel en vol, lecture de borne et arbitrage compris) — segment abandonné, non inscrit ; figeage du
  cache borné par la même échéance. Une finalité violée est inscrite dans l'état AVEC la correction qu'elle
  provoque et rapportée par l'exécution suivante si la première meurt avant son rapport. **Résultat `partiel` (BATTEMENT.md v1.3) : jamais `ok` tant que la couverture n'égale pas
  EXACTEMENT [déploiement, finalized]** — codes `differentiel_partiel` (progresse),
  `differentiel_retard_non_resorbe` (retard qui ne diminue pas, ou incomplet au-delà de la période / du tour),
  `differentiel_sans_progression` (rien vérifié ni figé) ; `refus/differentiel_finalite_violee` (un hash de
  borne a changé SOUS finalized — jamais absorbé dans un `ok`, même si la relecture redevient IDENTIQUE) ;
  `erreur/differentiel_couverture_absente` (garde : un différentiel sans bloc couverture ne sort ni `ok` ni
  `partiel`). Bloc `couverture` au FORMAT IMPOSÉ, nom pour nom, dans le battement et repris dans
  `health.json` : `{bloc_debut, bloc_fin_cible, bloc_fin_verifie, segments_verifies, segments_total, complet,
  motif_partiel}`, invariant `complet == (bloc_fin_verifie == bloc_fin_cible and segments_verifies ==
  segments_total)` gardé à l'écriture ; estimation (segments restants, retard, échéance estimée) à part, dans
  `couverture_estimation`. Un désaccord cache ↔ relecture est relu une fois
  en entier (KE#133/#156) puis ARBITRÉ par le fournisseur de référence sur les seuls blocs en désaccord : s'il
  rend le cache, c'est le fournisseur des journaux qui est incohérent (arrêt nommé, cache NON contredit).
  `--nouveau-tour` (à la main) force un tour neuf.
  **Finalité violée : jamais acquittée automatiquement** (décision du 2026-09-29). La preuve reste dans l'état et
  chaque exécution re-publie `refus/differentiel_finalite_violee` jusqu'à `python3 -B -m veilleur
  acquitter-finalite --preuve <empreinte exacte>` (archivée et journalisée, jamais effacée) ; un amorçage qui la
  constate n'écrit pas son registre. Procédure : `RUNBOOK.md`. `health.json` publie `budget_s` et, pour
  le complet, `tour_s` (`SPINDEX_VEILLEUR_TOUR_DIFFERENTIEL_COMPLET_S`, défaut = la période de la tâche).
  Coûts mesurés : `mesures/segments-2026-09-29.json`.
- **Compte à rebours J+90 en premier et isolé** ; lot gagnant non réclamé = alerte **P2** dédiée.
- **Battements** (`battement.py`, `backend/BATTEMENT.md` v1.2) : un fichier PAR TÂCHE
  (`battement-passe.json`, `battement-differentiel-quotidien.json`, `battement-differentiel-complet.json`),
  écrit APRÈS le travail, y compris en échec, avec les 429 comptés (`rpc`). **`health.json`** expose, par
  tâche, `silence_max_s` et `retard_bloc_max` DÉRIVÉS (période du timer + pire cas d'une exécution).
- **Cadence DÉCLARÉE PAR INSTANCE** (2026-09-23) : `SPINDEX_VEILLEUR_PLANIFICATEUR` et, par tâche,
  `SPINDEX_VEILLEUR_{PERIODE,PRECISION,DELAI_ALEATOIRE}_<TACHE>_S` — **obligatoires, sans défaut**
  (KE#73) : une clé absente est un ARRÊT qui la NOMME, et le service ne démarre pas. `a` bat toutes les
  5 min sous systemd, `b` toutes les 15 min sur GitHub Actions ; une période en dur dans le paquet
  faisait publier à `b` la borne de `a` (`silence_max_s` 431 s), donc « muette » à chaque passage. La
  FORMULE est inchangée : seules les trois valeurs viennent désormais du `.env`. Une tâche non planifiée
  sur une instance se déclare `non-planifiée` (→ `planifiée: false`, `silence_max_s: null`). Ces valeurs
  sont une **déclaration** : la surveillance doit la recouper avec les battements observés (`passe`,
  `ts`) et avec un plafond qu'elle tient elle-même — un service ne fixe pas le seuil auquel on l'accuse
  (KE#130).
- **429** : attente (`Retry-After`, sinon exponentielle bornée), jamais de découpage de plage ; la plage ne
  se découpe que sur une erreur de TAILLE reconnue.
- **Le fournisseur RPC est une DÉPENDANCE MESURÉE, pas une évidence** (2026-09-24). Les deux instances
  doivent tourner sur deux fournisseurs INDÉPENDANTS pour que leur accord prouve quelque chose ; le
  jour où `b` est passé sur dRPC, sa passe est tombée sur des refus que le code ne savait pas lire.
  Trois conséquences, toutes dans `fournisseurs.py` :
  - **table de signatures MESURÉES** — chaque forme de refus reconnue vient d'une capture réelle
    (`mesures/rpc-fournisseurs-2026-09-24.json`) et le banc la rejoue telle quelle. Un message inconnu
    est un ARRÊT qui nomme le remède, **jamais** une supposition : deviner « plage trop large » ferait
    redécouper à l'infini sur une panne qui n'a rien à voir. Aucun motif fourre-tout (KE#138).
  - **ce qui est spécifique à un fournisseur est CONFIGURABLE et DÉCLARÉ** — `SPINDEX_RPC_PROFIL`,
    `SPINDEX_RPC_MAX_LOG_SPAN`, `SPINDEX_RPC_USER_AGENT`, `SPINDEX_WINDOW_MAX_DEPTH`. Plages de
    journaux mesurées : **101 blocs** sur dRPC (dont le message en annonce 10 000 — il ment),
    50 000 sur publicnode, illimitée sur le nœud officiel mais plafonnée à 10 000 **journaux**.
    Le battement expose `plages_découpées` : non nul, c'est le signal de poser `MAX_LOG_SPAN`.
  - **une erreur applicative peut arriver dans un corps HTTP 4xx** (dRPC : 400). Elle ressort en
    `rpc_error` avec son `http_status` ; l'ordre du tri met la limitation de débit en premier et le
    fourre-tout de transport en dernier.
- **Fenêtre d'état sur un nœud d'ARCHIVE** : la dichotomie cherchait une profondeur REFUSÉE pour se
  borner ; sur dRPC, qui sert l'état à toute profondeur, elle n'en trouvait aucune et la mesure
  échouait — le nœud le plus généreux des trois était le seul déclaré inutilisable. Elle rend
  désormais un **MINORANT** déclaré (`borne: "minorant"`, « au moins N secondes », borné par
  `SPINDEX_WINDOW_MAX_DEPTH`). Deux garde-fous vont avec, et ils sont indissociables :
  - **témoin positif obligatoire** (KE#121) — la sonde doit savoir dire NON, prouvé à chaque mesure
    sur un bloc en avance de 1 000 000 sur la tête. Sans lui, « au moins N » serait aussi ce que
    rendrait une sonde en panne, et ce serait un feu vert permanent ;
  - **un minorant n'entre jamais dans la référence de dérive** — « au moins 8 h » relevé une fois
    ferait passer toute mesure exacte ultérieure pour un effondrement de 98 %. Un minorant au-dessus
    du besoin est un INFO ; en dessous, c'est un P1 `fenêtre_minorant_sous_besoin` qui dit « on ne
    sait pas » et nomme le réglage, jamais un P0 (on n'a pas prouvé la violation non plus).
- **Unités** (`systemd/`) : gabarits `@a` / `@b`, aucun `${VAR}` dans `ExecStart`, aucun `EnvironmentFile=`.
- **Garde de chaîne** (arbitrage 2026-09-22) : chaque passe, chaque différentiel et chaque vérification signée
  relisent `eth_chainId` AVANT toute autre lecture et le comparent à `SPINDEX_CHAIN_ID` ET à la chaîne de
  l'amorçage (`<état>/amorcage.json`). Écart : `erreur/chaine_inattendue`, rien n'est lu, aucun rapport, aucune
  attestation. Pas de registre : `erreur/amorcage_absent` (lancer `amorcer`). `eth_chainId` illisible : aucune
  lecture de la chaîne, compte à rebours depuis le cache figé seulement.
- **Codes de sortie des tâches planifiées** (arbitrage 2026-09-22) : la SANTÉ de la tâche, pas ses alertes. 0 si
  elle a fait son travail (battement `ok` ou `refus` : `alerte_P0`, `alerte_P1`, `differentiel_divergent`…), 20 si
  une section n'a pu être vérifiée, 2 sinon. Dérivé du battement ÉCRIT : l'un ne contredit jamais l'autre. Les
  alertes métier sont dans le battement, que la surveillance lit.
- **Déploiement sans semaine** : `AUCUNE_SEMAINE_DEPUIS_LE_DÉPLOIEMENT`, INFO explicite (dans `detail` du
  battement) tant que le déploiement a moins de 14 j (2 × la période hebdomadaire de REWARDS_SPEC §3), P1
  au-delà. Exige le témoin du constructeur ; sans lui, `NON_CALCULABLE` P1 comme avant.

## Amorçage — À FAIRE DÈS LE DÉPLOIEMENT DU CONTRAT (procédure)

Pourquoi tout de suite : le premier remplissage coûte ~1 appel par 1 000 blocs depuis le déploiement.
Quelques centaines d'appels le premier jour ; ~26 000 et des heures un mois plus tard.

Sur CHAQUE machine d'instance (`X` = `a` ou `b`), une fois `SpindexRewards` déployé :

1. Écrire `~/.config/spindex/veilleur-X.env` (modèle `.env.exemple`, TOUTES valeurs entre apostrophes) avec
   `SPINDEX_REWARDS_ADDR` = adresse créée, `SPINDEX_REWARDS_DEPLOY_BLOCK` = bloc du reçu de déploiement,
   `SPINDEX_VEILLEUR_INSTANCE='X'`, `SPINDEX_VEILLEUR_STATE_DIR` et `SPINDEX_VEILLEUR_BATTEMENT_DIR` =
   `~/.local/state/spindex/veilleur-X`. Vérifier : `python3 -B -m veilleur auditer-env ~/.config/spindex/veilleur-X.env`.
2. Depuis `~/stockslot/backend` :

   ```bash
   SPINDEX_VEILLEUR_ENV=~/.config/spindex/veilleur-X.env \
     python3 -B -m veilleur amorcer --instance X --tx-deploiement 0x<hash de la transaction de déploiement>
   ```

3. **L'amorçage n'est FAIT que si la commande sort 0 avec `"état": "AMORCÉ"`**, c'est-à-dire les quatre
   preuves à `ok: true` :
   - **A** : la transaction est réussie et a créé exactement l'adresse du `.env`, exactement au bloc du `.env` ;
   - **B** : le bloc de déploiement porte le journal du constructeur `OwnershipTransferred(0x0, …)` — preuve
     que le bloc est le bon ET que la lecture des journaux voit le contrat ;
   - **C** : le cache est figé jusqu'au `finalized` lu, point de reprise vérifié par hash ;
   - **D** : le différentiel complet rend `IDENTIQUE` (segmenté : sous `--échéance-ts`, sortie 20 `EN_COURS`, et
     la relance REPREND au premier segment non vérifié).

   Sortie 20 `EN_ATTENTE_DE_FINALITÉ` : `finalized` n'a pas encore dépassé le bloc de déploiement
   (~20 min) — relancer. Sortie 10 `REFUS` : lire `motifs`, corriger le `.env`, ne PAS activer.

   Un amorçage `AMORCÉ` écrit `<état>/amorcage.json` (chainId LU sur le nœud, adresse, bloc, transaction) :
   c'est la chaîne de référence des passes. **Instance amorcée avant le 2026-09-22 : relancer `amorcer`** (lecture
   seule, idempotent) pour l'écrire, sinon chaque passe bat `erreur/amorcage_absent`. Un amorçage REFUSE
   d'écraser le registre d'une autre chaîne.
4. Seulement alors : copier `systemd/*` dans `~/.config/systemd/user/`, `systemctl --user daemon-reload`,
   puis la commande `ensuite` imprimée par l'amorçage (`enable --now` des trois timers de l'instance X), et
   `loginctl enable-linger`.
5. Déclarer à la surveillance, par instance : `battement-passe.json`, `battement-differentiel-quotidien.json`,
   `battement-differentiel-complet.json` et `health.json` du dossier de battements (bornes à y LIRE).

## Banc

```bash
python3 -B -m pytest veilleur/bench/ -q                  # tests (dont test_exploitation.py)
python3 -B veilleur/bench/cassures.py                    # cassures volontaires, cible NOMMÉE exigée
python3 -B -m veilleur.bench.mesure_cout --banc          # coût par passe, complet vs incrémental
python3 -B -m veilleur.bench.e2e_anvil                   # vrai EVM + systemd-run TRANSITOIRE
python3 -B -m veilleur.outils.faire_lot_public           # refabrique le lot public
```

L'oracle du banc (`bench/fixtures/oracle-veilleur.json`) a été produit par **forge**, en faisant
tourner le VRAI `SpindexRewards` sur une copie jetable de `contracts/`. La reconstruction Python est
donc confrontée à des valeurs produites par le Solidity, jamais à sa propre formule.

## Ce qu'il ne fait pas

- il ne signe aucune transaction, et ne le peut pas : sa clé est Ed25519, l'EVM ne la reconnaît pas ;
- il ne détient aucun fonds, ne déclenche aucune action on-chain ;
- il ne se prononce pas sur ce qu'il n'a pas pu lire.

Détail, limites et questions ouvertes : `backend/rapports/veilleur.md`.
