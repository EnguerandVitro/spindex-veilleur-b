# SPINDEX — veilleur, instance `b`

Le second veilleur, sur une infrastructure et un compte **indépendants de la machine du keeper**.

La décision du 2026-09-21 exige deux instances. Aujourd'hui l'instance `a` tourne sous systemd sur la
machine du keeper : si cette machine tombe, ou si elle est compromise, **le témoin tombe avec elle**.
Ce dépôt est le témoin qui ne tombe pas avec elle. Il exécute le **même code scellé** que `a`, sur la
**même chaîne**, et publie ce qu'il voit là où la surveillance peut le lire sans jamais rien pouvoir
écrire chez nous.

---

## Ce que ce montage NE protège PAS — à lire avant tout le reste

Écrit noir sur blanc, parce qu'un témoin dont on croit qu'il protège plus qu'il ne protège est pire
qu'un témoin absent.

1. **GitHub voit les secrets.** L'URL RPC et la clé d'attestation de `b` sont stockées chez GitHub et
   déchiffrées dans la machine virtuelle du job à chaque exécution. GitHub, et quiconque obtient les
   droits d'administration du dépôt, peut les lire ou les remplacer. La clé `b` est donc **une clé de
   moindre confiance que celle de `a`**, qui ne quitte jamais sa machine. Conséquence pratique : un
   feu vert de `b` **ne remplace pas** celui de `a`, il le **recoupe**.
2. **Le job peut être retardé, ou ne pas partir du tout.** `schedule` ne descend pas sous 5 minutes,
   et GitHub annonce lui-même des retards et des passages sautés en période de charge. De plus, les
   workflows planifiés sont **désactivés après 60 jours sans activité sur le dépôt**. Un `b` silencieux
   n'est pas forcément un `b` mort — mais on ne peut pas faire la différence, donc la surveillance
   doit traiter le silence comme un silence.
3. **Le propriétaire du compte peut supprimer le job, l'historique, ou le dépôt entier.** Rien ici
   n'est opposable à qui détient le compte. Une branche `attestations` est une trace, pas une preuve
   d'existence : une signature prouve ce qui est là, jamais ce qui manque.
4. **Une divergence entre `a` et `b` ne dit pas laquelle des deux ment.** Elle dit qu'il faut
   s'arrêter et regarder à la main. C'est déjà énorme — aujourd'hui, personne ne verrait rien — mais
   ce n'est pas un arbitrage automatique, et il ne faut pas en écrire un.
5. **`b` n'est pas indépendant du RPC.** Les deux instances lisent la chaîne par un fournisseur RPC.
   Si elles utilisent le même point d'entrée, un nœud menteur les trompe toutes les deux d'un coup.
   **Poser une URL RPC DIFFÉRENTE de celle de `a`** est ce qui donne sa valeur au montage ; le secret
   existe pour ça.
6. **La copie du code vient de la machine du keeper.** `outils/resynchroniser.sh` est lancé là-bas par
   un humain. Le code est public et son empreinte est vérifiable des deux côtés, donc ce n'est pas un
   canal de données — mais ce n'est pas non plus une indépendance totale, et il faut le savoir.
7. **Les actions tierces (`actions/checkout` v4.4.0, `actions/upload-artifact` v4.6.2) sont épinglées
   par empreinte de commit depuis le 2026-09-28** — mais leur CODE reste celui de tiers, et le runner
   aussi. Le jeton d'écriture n'est posé qu'à l'étape « Publier » (`persist-credentials: false`) :
   pendant que le code qui lit la chaîne tourne, aucun identifiant n'est sur le disque.

8. **L'indépendance de `b` porte sur les JOURNAUX, PAS sur l'ÉTAT** (arbitrage du 2026-09-28, KE#127 :
   un verdict nomme son périmètre). dRPC gratuit ne sert plus l'état à un bloc numéroté ; `b` lit donc ses
   journaux chez dRPC (secret `SPINDEX_B_RPC_URL`) et **toutes ses lectures d'état — têtes, blocs, sondes de
   fenêtre, `strandedBurn`, tout `eth_call` à un bloc — chez le RPC officiel public, qui est celui de `a`**
   (`config/chaine-46630.json` → `rpc_etat`). Un feu vert de `b` recoupe donc indépendamment les
   événements, le cache et les racines merkle reconstruites ; il ne recoupe PAS ce que le nœud officiel
   dit de l'état — un nœud officiel menteur tromperait `a` et `b` du même coup sur l'état. `health.json`
   et chaque battement publient les deux HÔTES par rôle (`fournisseurs`), jamais une URL — vérifié sur les
   FICHIERS écrits (banc de la famille, et jambe L du banc de `b`), pas sur la déclaration. Mesuré le
   2026-09-28 depuis la machine du keeper : passe VERTE, 286 appels, fenêtre ≈ 1 590 s. **Non vérifié :
   que le RPC officiel réponde depuis un runner GitHub** (le premier job le dira ; un refus y sera nommé).

9. **La fraîcheur de `b` dépend d'un déclencheur EXTERNE** (depuis le 2026-09-28) : la machine de
   surveillance lance `b` par `workflow_dispatch` toutes les 15 min, et une fois par jour pour le
   différentiel quotidien. Si cette machine tombe, `b` ne tourne plus que sur le cron GitHub (filet), bridé :
   127 à 471 min mesurés. La surveillance doit donc lire `période_attendue_s` pour la fraîcheur et
   `silence_max_s` pour l'alerte de silence ; un `b` silencieux 9 h n'est pas en faute, un `b` qui bat
   toutes les 15 min en lisant une tête figée l'est en 15 min (`retard_bloc_max`, nominal ;
   `retard_bloc_max_filet` n'est publié qu'à part). Et le déclencheur est lui-même un point unique :
   c'est la machine qu'il est censé recouper qui le porte.

---

## Ce que cette copie embarque

`veilleur/` est une copie du paquet scellé `backend/veilleur`.

> **État au 2026-09-29.** La copie est prise sur le **scellé** de la famille qui rend les différentiels
> REPRENABLES par segments et publie le bloc `couverture` de BATTEMENT.md v1.3 (`FIGE.json` `ad1f5368…`,
> empreinte `e07912f2…`). **Ce scellé n'est pas encore livré** : `a` publie `e357d89a…`, donc
> `resynchroniser.sh` affiche **DÉSACCORD** jusqu'à la livraison de `a` sur ce scellé, puis se relance sans
> argument (source = release en service, qui ramène aussi `veilleur/LIVRAISON.json`, absent d'une copie prise
> sur l'arbre de travail). `config/chaine-46630.json` vise le `SpindexRewards` post-C-4 `0x34ebcae3…`
> (bloc 125 796 406), écrit par `outils/maj_chaine.py`, preuves sur la chaîne comprises.

La règle d'exploitation reste : `b` doit exécuter le code que `a` exécute, pris dans une copie scellée,
sinon une divergence entre les deux se lirait comme un désaccord sur la chaîne alors que ce serait un
désaccord sur le code.

La famille livre souvent. **Après chaque livraison, relancer `outils/resynchroniser.sh`** (sur la
machine du keeper), rejouer le banc, committer, pousser. Le script fait lui-même la vérification
croisée avec le `health.json` de l'instance `a` et affiche `ACCORD` ou `DÉSACCORD` : tant qu'il dit
`DÉSACCORD`, les deux instances n'exécutent pas le même code et leur accord ne veut rien dire.

### Comment on prouve que la copie est bien la version scellée

Trois ancrages, et ils ne viennent pas du même endroit (`outils/sceau.py` les vérifie **au démarrage
de chaque job**, avant toute lecture de la chaîne) :

| # | Ancrage | Ce qu'il attrape | D'où vient la référence |
|---|---|---|---|
| 1 | `SCEAU.json` | une modification locale de la copie | de moi — donc insuffisant seul |
| 2 | `veilleur/FIGE.json` | une copie qui diverge du scellé | **de la famille elle-même** |
| 3 | `empreinte_sources()` | le code réellement exécuté | **publiée en service par l'instance `a`** |

L'ancrage 3 est le seul vérifiable de l'extérieur : l'instance `a` écrit la **même** valeur dans son
`health.json` et dans chacun de ses battements, à chaque passe. Valeur de la copie (scellé du
2026-09-29 ; `a` publiera la même une fois livrée sur ce scellé) :

```
e07912f2f91441ef6f0c3197e1f35f0502812938b5ad3b8564b654a7daa527fa
```

Deux instances qui ne portent pas cette même empreinte n'exécutent pas le même code, et leur accord
— comme leur désaccord — ne voudrait rien dire.

| 4 | `outils/conformite.py vérifier` | une copie (et son scellé) **périmée** | **du contrat**, calculée par `cast` |

L'ancrage 4 existe parce que les trois premiers ont laissé passer un incident réel : du 2026-09-24 au
2026-09-28, la copie portait la convention merkle d'**avant** la séparation de domaine (lot sécurité
C-4) **avec son `FIGE.json` d'avant** — les deux s'accordaient parfaitement, et `b` calculait des
feuilles que le contrat redéployé n'acceptera jamais. `config/vecteurs-convention.json` porte des
feuilles dorées (`claim` et `draw`, 4 vecteurs chacun, dont l'ancre chiffrée de la red team) calculées
par `cast` — implémentation indépendante de keccak et d'`abi.encode` — depuis les préimages d'étiquette
**lues dans `contracts/src/SpindexRewards.sol`**. Chaque job exige que la copie les retrouve au bit
près avant de lire la chaîne ; une copie sans étiquette est nommée comme la collision F03.

Sur la machine du keeper, deux contrôles de plus (banc, jambe G, et `resynchroniser.sh`) :
`contrôler-générateur` (le fichier de vecteurs est un fichier GÉNÉRÉ : il est confronté à ce que son
générateur produit **aujourd'hui** depuis la source — si le contrat ou la convention changent, il
rougit, KE#148) et `recouper-source` (copie, famille scellée `backend/veilleur` et autorité amont
`contracts/rewards` portent la même convention, le scellé de la famille est valide, et la copie porte
**le `FIGE.json` de la famille d'aujourd'hui**, KE#137). **Ne jamais régénérer les vecteurs sans avoir
resynchronisé la copie et lu le diff des vecteurs** : régénérer seul, c'est rafraîchir l'épingle
machinalement (KE#147).

S'ajoutent les contrôles de **couverture** (KE#111) : le sceau refuse un manifeste vide, refuse un
intrus sous `veilleur/` (un `.py` de plus à la racine **déplacerait** `empreinte_sources()`), et exige
que **tout** fichier exécuté ait été croisé avec le scellé de la famille.

---

## Le fournisseur RPC de `b` : dRPC, et le profil qui va avec

Le secret `SPINDEX_B_RPC_URL` pointe **dRPC** (fournisseur indépendant de celui de `a`). dRPC refuse toute
plage de journaux de plus de **101 blocs**, en HTTP 400, avec un message qui annonce 10 000 (rapport
veilleur §13). `config/chaine-46630.json` déclare donc `"rpc_profil": "drpc"`, et `outils/preparer.py`
l'écrit en `SPINDEX_RPC_PROFIL` dans le `.env`. Le domaine de l'URL secrète est confronté aux profils
**mesurés** du paquet scellé : URL dRPC sans ce profil, ou profil que l'URL contredit, c'est un ARRÊT avant
toute lecture (l'URL n'est jamais imprimée). Le banc (jambe H) le prouve par comportement, contre un faux
dRPC local (ports 18570-18579) : avec le profil, 1 000 blocs lus sans un refus ; sans lui, refus.

dRPC (plan gratuit) rend aussi, par moments, un **HTTP 408 « Request timeout »** sur une plage pourtant
valide (run 36469251579). Le paquet le classe `delai_fournisseur` : **relance bornée** à attente
croissante (5 essais, 2 → 30 s, déclarés dans le profil `drpc`, sans défaut), jamais de redécoupage,
puis échec nommé. Et si l'amorçage échoue quand même, l'étape « Publier » sauve l'**état partiel**
(`outils/etat_partiel.sh`, commit non signé qui le dit) : le job suivant reprend au dernier segment figé
(un segment tous les ~200 appels) au lieu de repartir du bloc de déploiement.

**⚠️ dRPC gratuit ne sert plus l'état par numéro de bloc (mesuré le 2026-09-28, run 36475098966).**
`eth_call` à tête−k refusé pour k = 0 à 8 000 (`Unknown state. First available state is 1`, 8/8), alors
que `latest` répond et que sa tête n'est pas en retard sur le nœud officiel. Les journaux (et donc
l'amorçage) passent ; la section `burn` et la sonde de fenêtre, qui lisent l'état à un bloc ÉPINGLÉ, ne
peuvent pas passer — le paquet le dit désormais (`etat_indisponible`, « le nœud n'est pas utilisable »).
Mesuré le même jour sur les deux autres fournisseurs : officiel ≥ 6 000 blocs (≈ 940 s), publicnode
entre 100 et 1 000 blocs (16 à 156 s, sous le besoin de 480 s). Aucun fournisseur indépendant mesuré ne
convenait à l'ÉTAT : **résolu le 2026-09-28 par l'option 2 (un fournisseur par rôle) — voir la limite
n°8** en tête de ce fichier. Conséquence à garder en tête : les BORNES de lecture des journaux (tête,
`finalized`) et les HASH de blocs viennent du nœud OFFICIEL (KE#130 : la borne vient de la source, pas
du sujet) ; les journaux de dRPC n'entrent dans le cache qu'après avoir prouvé que dRPC a atteint la fin
du segment et que leurs `blockHash` sont ceux que lit le nœud officiel. Ce que ce lien ne couvre PAS : un
bloc pour lequel dRPC OMETTRAIT des journaux sans rien rendre — il faudrait une seconde source de journaux.

**Les différentiels et la preuve D sont REPRENABLES (2026-09-29).** La famille `veilleur` les découpe en
segments de 20 200 blocs à bornes fixes (`veilleur/segments.py`) : chaque segment vérifié laisse un point de
reprise durable dans `etat/differentiel-{quotidien,complet}.json`, que la branche `attestations` restaure. Chaque
exécution s'arrête PROPREMENT à `budget_veiller_s` (1 740 s, compté depuis le début de « Veiller » ; le segment
en vol a une échéance DURE à +120 s), publie un battement `partiel` avec son bloc `couverture` (jugement
**EN_COURS** s'il progresse — ni VERT ni ROUGE, avertissement dans l'exécution GitHub —, ROUGE s'il ne résorbe pas
son retard) et la suivante reprend au premier segment non vérifié. Un job TUÉ au délai est dit comme tel par la
Barrière (`travail/ETAPE.json` : étape en cours), jamais « rien n'a été lu ». Mesuré le 2026-09-29 (`veilleur/mesures/segments-2026-09-29.json`) :
**200 appels et ≈ 36 s par segment chez dRPC**, ≈ 48 segments (≈ 2,2 jours de chaîne à 5,08 blocs/s) par
exécution. Un amorçage à froid dont la preuve D (ou le figeage C) ne tient pas dans une exécution rend
`EN_COURS` côté paquet (sortie 20) — à ne pas confondre avec le verdict `EN_COURS` d'un différentiel : le JOB, lui,
est ROUGE « amorçage interrompu » (pas de registre, pas de lot signé) —, l'état partiel est publié, et le job
suivant le poursuit. Ce qui n'est PAS repris : la PASSE elle-même (un
cache perdu sur un contrat âgé se re-fige par pas de 200 appels, sauvés par l'état partiel, mais la passe qui
le fait n'a pas de budget).

**Propriété nouvelle, à garder en tête : tout ce qui est dans `etat/` survit à un échec.** C'est voulu pour
le cache, et c'est pourquoi deux gardes l'accompagnent : un cache que D a CONTREDIT est écarté hors de
`etat/` par `executer.sh` avant toute publication (sinon chaque job le reprendrait et refuserait pour
toujours), et `outils/etat_sain.sh` refuse de publier un `etat/` qui contient un fichier de type secret
(`*.hex`, `*.env`, `attest-*`, `*.pem`, `*.key`).

## Au redéploiement : UNE commande pour la configuration de chaîne

```bash
python3 -B outils/maj_chaine.py --manifeste ~/stockslot/contracts/deploy/manifestes/deploiement-46630-<date>.json
```

Elle refuse un manifeste dont les contrôles ne sont pas tous réussis, puis prouve **sur la chaîne** (RPC public,
lecture seule) le reçu de création, le bloc et l'empreinte du code de `SpindexRewards`, et **en dernier** que
le contrat est postérieur à C-4 (`TAG_CLAIM()` / `TAG_DRAW()` = étiquettes des vecteurs dorés). L'ancien déploiement (`…041522Z`, pré-C-4) y était refusé sur ce seul dernier point ; le
redéploiement du 2026-09-28 (`…165955Z`) passe les quatre preuves. `--a-blanc` vérifie sans écrire. Au premier job
qui suit, `executer.sh` archive l'état restauré de l'ancien contrat et ré-amorce (jambe I du banc).

## La cadence : un déclencheur externe, et le cron GitHub comme FILET (mesuré)

**Mesure, 2026-09-28 (API GitHub, dépôt `spindex-veilleur-b`)** : 29 exécutions planifiées `*/15` du
2026-09-23T22:57Z au 2026-09-28T18:12Z, écarts de **127 à 471 min, médiane 238 min**. GitHub bride les
crons des dépôts publics : `*/15` n'y veut pas dire « toutes les 15 minutes ». Dériver le silence admissible
du cron déclaré publiait ≈ 1 081 s et la surveillance voyait `b` muette en permanence.

Depuis le 2026-09-28, `b` publie **deux bornes distinctes et nommées** par tâche (`health.json`) :

| tâche | `période_attendue_s` (fraîcheur) | déclencheur | `silence_max_s` (admissible) |
|---|---|---|---|
| `passe` | 900 | `workflow_dispatch` toutes les 15 min par la machine de surveillance | ≥ 32 400 s : filet = cron GitHub, 471 min mesurés + marge → 9 h |
| `differentiel-quotidien` | 86 400 | `workflow_dispatch` une fois par jour (04:37 UTC) — déclencheur externe SEUL, aucun filet | dérivé de la période (86 400 + 600 + durée) |
| `differentiel-complet` | 21 600 | `workflow_dispatch` toutes les 6 h — **déclencheur À CRÉER côté exploitation** | dérivé de la période (21 600 + 600 + pire) |

Les deux différentiels publient `budget_s` = 1 740 s (le pire cas publié en dérive : budget + un segment en vol,
et non plus une durée qui croît avec l'âge du contrat), et le complet `tour_s` = 604 800 s : **un TOUR complet
par semaine**, relu depuis le déploiement sur autant d'exécutions qu'il faut ; entre deux tours, une exécution
rend `TOUR_À_JOUR` en quelques secondes sans rien relire. Le QUOTIDIEN ne relit plus que le neuf (≈ 21,7
segments ≈ 13 min par jour de chaîne chez dRPC, plus aucun recouvrement de 200 000 blocs).

**Horizon du tour hebdomadaire sur dRPC gratuit, calculé sur la mesure** : un tour à l'âge A jours coûte
≈ 13·A min de lecture ; à 4 exécutions de 29 min par jour, il dure ≈ A/7,8 jours ⇒ tenable jusqu'à
**A ≈ 54 jours**. Au-delà, le tour dépasse sa semaine et le battement le dit (`differentiel_retard_non_resorbe`) :
c'est le signal d'un plan dRPC payant (plages plus larges ⇒ 10 à 100 fois moins d'appels), pas d'un délai plus
long. Chaque exécution longue retient la file `concurrency` du dépôt : une passe au plus est écartée par
exécution du complet.

**Sérialisation des tâches (décision du 2026-09-29) — et la borne qu'elle impose à la `passe`.** Un seul groupe
`concurrency` pour les trois tâches : deux jobs parallèles partiraient du même `etat/` restauré et publieraient chacun
`etat/` en entier sur `attestations` (cache des journaux, points de reprise des différentiels, `health.json`) ; la
seconde poussée écraserait la première, et un rebase ne réconcilie pas deux curseurs de cache divergents. Un groupe
par tâche exigerait un `etat/` PARTITIONNÉ par tâche (cache partagé en lecture seule) : chantier à part. Conséquence
chiffrée : pendant un `differentiel-complet`, la `passe` attend. Durée d'un complet : ≤ budget 1 740 s + échéance
dure 120 s + jugement/lot/publication (≈ 1-3 min) ≈ **31-34 min en nominal**, **45 min au pire** (délai du job).
L'intervalle entre deux passes peut donc atteindre **900 s + 2 700 s = 3 600 s** au pire (≈ 2 900 s en nominal), 4
fois par jour : une surveillance qui juge la `passe` sur sa période de 900 s doit tolérer ce trou quand le
`differentiel-complet` du même dépôt est en cours (lisible : run nommé `differentiel-complet`, `run-name`), ou
lever une P2 de période manquée qui sera, dans ce cas, VRAIE mais attendue.
Les exécutions portent le nom de leur tâche (`run-name`), exactement celui de l'index des battements.

Chaque lot publié porte le **dernier battement connu de CHAQUE tâche**, octet pour octet et avec son
horodatage d'origine, indexé et signé dans le manifeste (`battements`) ; une tâche qui n'a jamais tourné y
est DITE absente.

## Ce que le job publie, et pourquoi les deux

- **un artefact** attaché à l'exécution : il survit à un échec de poussée, porte les journaux bruts, et
  existe même quand la branche n'existe pas. Mais il expire (90 jours) et il faut un compte pour le
  lire : il ne peut pas être le canal de la surveillance. C'est le **filet** ;
- **un commit sur la branche `attestations`** : permanent, horodaté par GitHub, lisible par un simple
  `git fetch` depuis n'importe où, sans compte ni jeton si le dépôt est public. C'est le **canal**.

La branche contient :

```
courant/            le dernier lot signé — c'est ce que la surveillance lit
lots/<date>-<run>/  l'histoire (rouge, verdicts, et un lot par jour)
etat/               l'état restauré à l'exécution suivante (registre d'amorçage…)
verifier_lot.py     le vérificateur, pour qu'un lecteur n'ait besoin de rien d'autre
```

Chaque lot porte `MANIFESTE.json` (l'empreinte de chaque fichier + le contexte d'exécution) et
`SIGNATURE.json` (Ed25519 de ce manifeste, par la clé de `b`, dans un **domaine distinct** de celui
des feux verts : `spindex-veilleur-b-lot/1`). Sans cela, recopier `battement-passe.json` ne prouverait
rien — n'importe qui pouvant écrire dans le dépôt fabriquerait un battement vert pour un veilleur mort.

**Le lot est publié même quand le jugement est ROUGE**, et il porte son jugement : un veilleur qui se
tait quand il trouve quelque chose serait pire qu'un veilleur absent. Le banc le vérifie.

---

## Marche à suivre — mise en route

> **Règle absolue, valable partout ci-dessous : la clé privée ne doit JAMAIS être tapée, collée ou
> affichée dans un terminal — ni local, ni SSH, ni partagé.** Elle passe du fichier au presse-papiers,
> et du presse-papiers au formulaire de GitHub, dans un navigateur. Aucune commande ne la reçoit en
> argument : les messages d'erreur des outils réimpriment la commande, jetons compris (fuite
> `VERCEL_TOKEN` du 2026-09-11).

### 1. Créer le dépôt GitHub

Sur un **compte GitHub qui n'est pas celui du keeper** (c'est tout l'objet du montage), créer un
dépôt **public**, vide, par exemple `spindex-veilleur-b`.

Public, et non privé, pour trois raisons : les minutes d'Actions sont gratuites sur un dépôt public
(une exécution toutes les 15 minutes dépasserait le quota gratuit d'un dépôt privé) ; la surveillance
peut alors tirer la branche `attestations` **sans compte ni jeton** ; et il n'y a rien à cacher — la
vérification ne porte que sur des données publiques, c'est précisément ce qui la rend rejouable par
un tiers. Les secrets d'Actions restent chiffrés et ne sont **pas** publics.

Dans **Settings → Actions → General** :
- *Actions permissions* : n'autoriser que les actions de GitHub et celles explicitement listées ;
- *Fork pull request workflows* : **désactiver** l'exécution des workflows venus de forks. Sans ça,
  une pull request d'un inconnu pourrait faire tourner du code dans un job qui voit les secrets ;
- *Workflow permissions* : lecture seule par défaut (le workflow demande lui-même `contents: write`).

### 2. Créer la clé d'attestation de `b` — hors ligne, sur votre machine

**Sur votre Mac, pas sur l'EC2**, dans un terminal qui n'est pas partagé :

```bash
mkdir -p ~/.spindex && chmod 700 ~/.spindex
umask 077
python3 - <<'EOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
import os
k = Ed25519PrivateKey.generate()
brut = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
chemin = os.path.expanduser("~/.spindex/veilleur-b-attest.hex")
fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, brut.hex().encode() + b"\n"); os.close(fd)
pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
print("clé PUBLIQUE de l'instance b (à noter, à diffuser) :", pub)
print("la clé privée n'est PAS affichée ; elle est dans", chemin)
EOF
```

**Notez la clé publique** : c'est l'ancre de confiance. Elle va chez les signataires du Safe et sur la
machine de surveillance. La clé privée reste dans ce fichier, et nulle part ailleurs.

> Cette clé est **Ed25519**, et ce choix est constitutif : l'EVM ne reconnaît aucune signature
> Ed25519. Ce qui vérifie ne peut donc pas signer une transaction — ce n'est pas une promesse
> d'exploitation, c'est une propriété de l'algorithme.
>
> **La clé de l'instance `a` ne doit JAMAIS quitter sa machine.** `b` a sa propre clé, et c'est ce qui
> permet de dire « les deux instances ont attesté » plutôt que « une clé a signé deux fois ».

### 3. Poser les deux secrets dans GitHub

Dans le dépôt : **Settings → Secrets and variables → Actions → New repository secret**.

| Nom du secret | Contenu |
|---|---|
| `SPINDEX_B_ATTEST_KEY_HEX` | les 64 caractères hexadécimaux du fichier créé à l'étape 2 |
| `SPINDEX_B_RPC_URL` | une URL RPC de la 46630 — **différente de celle de `a`** (voir limite n°5) |

Pour la clé, **sans jamais l'afficher** :

```bash
pbcopy < ~/.spindex/veilleur-b-attest.hex      # macOS : fichier → presse-papiers, rien à l'écran
```

puis ⌘V dans le champ du formulaire GitHub, et **videz le presse-papiers ensuite** (`pbcopy </dev/null`).

Aucun de ces deux secrets ne doit apparaître dans un fichier du dépôt. `config/chaine-46630.json` ne
contient que des valeurs publiques (adresses, blocs, hash de transaction).

### 4. Pousser ce dossier dans le dépôt

Depuis la machine qui détient ce dossier :

```bash
cd ~/stockslot/veilleur-b
git remote add origin https://github.com/<compte>/spindex-veilleur-b.git
git push -u origin master        # ou `main`, selon ce que GitHub a créé
```

### 5. Activer le workflow

Onglet **Actions** du dépôt → activer les workflows si GitHub le demande → **veilleur-b** →
**Run workflow** (`workflow_dispatch`) pour un premier passage à la main.

Le premier passage **amorce** : il relit toute la chaîne depuis le bloc de déploiement pour prouver
qu'il regarde la bonne, ce qui prend quelques minutes. Les suivants durent quelques secondes.
Ensuite, la planification `*/15` prend le relais toute seule.

### 6. Vérifier que l'attestation de `b` est bien signée par VOTRE clé

C'est l'étape qui donne sa valeur aux cinq précédentes. Depuis n'importe quelle machine :

```bash
git clone --depth 1 --branch attestations \
    https://github.com/<compte>/spindex-veilleur-b.git /tmp/attest-b
cd /tmp/attest-b
python3 -B verifier_lot.py --lot courant --clé-publique <la clé publique notée à l'étape 2>
```

Attendu : `LOT AUTHENTIQUE`, code de sortie 0. La commande **refuse** si la clé publique n'est pas
fournie : une signature vérifiée contre la clé que le document transporte n'authentifie personne.

Trois choses à regarder dans la sortie :
- `signé_par` — c'est bien votre clé, celle notée à l'étape 2 ;
- `empreinte_sources` — c'est bien `e07912f2f91441ef…` (valeur de `SCEAU.json`), la même que celle publiée par `a` ;
- `jugement` — `VERT`, ou `ROUGE` avec ses motifs nommés.

Et si vous changez un octet de `courant/health.json`, la commande doit **refuser**. Faites-le une
fois : un vérificateur qu'on n'a jamais vu dire non ne prouve rien.

---

## Comment la surveillance voit l'instance `b`

Le chemin le plus simple qui ne donne à `b` **aucun** accès à la machine du keeper : la surveillance
**tire**, `b` ne pousse jamais chez nous.

```
GitHub Actions ──signe──> branche `attestations` (publique)
                                      │
                      git fetch (lecture seule, sans jeton)
                                      ▼
            machine de surveillance : vérifie la signature contre l'ancre,
            puis dépose dans /var/lib/spindex-surveillance/veilleur-b/
```

Aucun compte, aucune clé, aucun port ouvert chez nous. La surveillance lit ensuite ces fichiers
exactement comme elle lit ceux de `a` — `sources.exemple.json` prévoit **déjà** une entrée
`veilleur-b` avec ces chemins.

Ce qu'il reste à faire **côté surveillance** (famille scellée, atelier en cours : non codé ici) est
écrit en détail dans **`DEMANDE-SURVEILLANCE.md`**.

---

## Banc — la preuve, en local

Les deux scripts exécutent `outils/executer.sh`, c'est-à-dire **exactement ce que lance le job** : ce
n'est pas une reproduction des étapes, c'est le même code.

```bash
cd ~/stockslot/veilleur-b
# une clé JETABLE de banc (jamais celle de production)
python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
from cryptography.hazmat.primitives import serialization as s
print(K.generate().private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()).hex())
" > /tmp/cle-banc.hex

# BANC_PROJET=<racine du projet> si ce dépôt n est pas rangé dans le projet (jambe G : conformité à la SOURCE)
bash banc/preuves.sh  /tmp/banc-b /tmp/cle-banc.hex     # 14 jambes (A à N), 64 contrôles, lecture seule
bash banc/cassures.sh /tmp/banc-b /tmp/cle-banc.hex     # 47 cassures : chaque garde est-elle portante ?
```

`preuves.sh` : chaîne inattendue → ROUGE · contrôle rouge → ROUGE · tout normal → VERT (témoin
positif) · copie modifiée → ARRÊT · secret absent → ARRÊT · `verifier_lot.py` seul, sans paquet
`veilleur` — la situation exacte de la machine de surveillance — accepte le lot intact, **refuse** un
octet modifié, et **refuse** sans ancre de confiance. Les deux cas rouges doivent **aussi** avoir
publié leur lot signé.

**À rejouer depuis un clone frais**, pas seulement dans l'arbre d'origine : c'est comme ça qu'a été
trouvé le `SPINDEX_CONTRACTS_DIR` manquant, qui marchait ici (le vrai `contracts/` était à côté) et
serait mort sur le runner.

`cassures.sh` : la cassure **maximale** d'abord (si le banc ne rougit pas quand tout est cassé, il ne
rougira jamais), puis une par garde. `python3 -B` et purge des `__pycache__` entre chaque essai
(KE#117), sauvegarde + `trap` + vérification que l'arbre est revenu à l'identique (KE#122).

---

## Entretien

- **Après chaque livraison de la famille `veilleur`** : lancer `outils/resynchroniser.sh` sur la
  machine du keeper, rejouer les deux scripts du banc, committer en nommant la release, pousser, et
  prévenir le coordinateur (la surveillance compare les empreintes des deux instances).
- **Mettre à jour les actions épinglées** : relire le diff de l'action, puis remplacer l'empreinte
  (`gh api repos/actions/<action>/git/ref/tags/<vX.Y.Z>`, déréférencer si l'objet est un `tag`) et le
  commentaire de version, dans le même commit.
- **La branche `attestations` grossit** d'environ vingt kilo-octets par passage. La remettre à plat
  est un geste **humain**, une fois par an, jamais une poussée en force automatique — elle effacerait
  l'histoire que la branche existe pour garder.
- **Les workflows planifiés sont désactivés après 60 jours sans activité** sur le dépôt. Les commits
  du job n'y suffisent pas toujours : le vérifier à chaque entretien.
- **Si la clé de `b` doit être remplacée** : créer la nouvelle (étape 2), remplacer le secret (étape
  3), **puis** diffuser la nouvelle ancre. Tant que l'ancienne ancre est posée quelque part, les lots
  neufs y seront refusés — bruyamment, ce qui est le comportement voulu.
