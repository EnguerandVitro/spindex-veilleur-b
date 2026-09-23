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
python3 -B -m veilleur surveiller --depuis-zéro                             # reconstruction complète, à la main
```

- **Lecture incrémentale** (`journaux.py`) : journaux figés jusqu'à `finalized` seulement, par segments
  immuables ; le hash du dernier bloc figé est **relu sur la chaîne à chaque passe** (divergence : on
  recule et on le dit). La reconstruction **complète** reste la référence (vérificateur public).
- **Différentiels** : QUOTIDIEN = blocs figés depuis le précédent différentiel réussi + un segment de
  recouvrement + toute plage re-figée après une reprise forcée (coût = volume du jour) ; COMPLET
  hebdomadaire = tout depuis le déploiement.
- **Compte à rebours J+90 en premier et isolé** ; lot gagnant non réclamé = alerte **P2** dédiée.
- **Battements** (`battement.py`, `backend/BATTEMENT.md` v1.2) : un fichier PAR TÂCHE
  (`battement-passe.json`, `battement-differentiel-quotidien.json`, `battement-differentiel-complet.json`),
  écrit APRÈS le travail, y compris en échec, avec les 429 comptés (`rpc`). **`health.json`** expose, par
  tâche, `silence_max_s` et `retard_bloc_max` DÉRIVÉS (période du timer + pire cas d'une exécution).
- **429** : attente (`Retry-After`, sinon exponentielle bornée), jamais de découpage de plage ; la plage ne
  se découpe que sur une erreur de TAILLE reconnue.
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
   - **D** : le différentiel complet rend `IDENTIQUE`.

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
