---
title: Ce qu'il reste à faire côté surveillance pour que l'instance b compte
date: 2026-09-23
de: atelier veilleur-b (GitHub Actions)
à: coordinateur
statut: demande — RIEN n'a été codé dans `backend/surveillance/` (famille scellée, atelier en cours)
---

# Demande au coordinateur — voir l'instance `b`

L'instance `b` existe, tourne et publie. Tant que la surveillance ne la lit pas, la P1
`veilleur_instance_manquante` reste ouverte **et elle a raison de rester ouverte** : une instance que
personne ne lit n'est pas un témoin.

Cinq points. Les trois premiers sont nécessaires pour fermer la P1 ; les deux derniers sont des
décisions que je n'ai pas le droit de prendre à la place du coordinateur.

---

## 1. Déclarer `veilleur-b` dans les sources — c'est ce qui ferme la P1

`regles.py:veilleurs()` compte `[s for s in ctx["sources"] if s["service"] == "veilleur"]`. Il suffit
donc d'ajouter l'entrée dans le fichier de sources **en service**
(`~/.config/spindex/testnet/surveillance-sources.json`). `sources.exemple.json` la prévoit déjà, aux
chemins exacts ci-dessous — rien à inventer :

```json
{"service": "veilleur", "instance": "b",
 "health": "/var/lib/spindex-surveillance/veilleur-b/health.json",
 "battements": "/var/lib/spindex-surveillance/veilleur-b",
 "taches": ["passe", "differentiel-quotidien", "differentiel-complet"],
 "derniere_passe": "/var/lib/spindex-surveillance/veilleur-b/derniere-passe.json",
 "verdicts": "/var/lib/spindex-surveillance/veilleur-b/verdicts"}
```

⚠️ **À ne faire qu'APRÈS le point 2 et le point 3.** Déclarée sans le tirage, `b` serait muette ;
déclarée sans la correction de cadence, elle serait muette *en permanence*. Une alerte permanente est
une alerte que personne ne lit.

---

## 2. Le tirage : la surveillance TIRE, `b` ne pousse jamais

C'est le chemin le plus simple qui ne donne à `b` **aucun** accès à la machine du keeper : aucun
compte, aucune clé, aucun port ouvert, aucune entrée dans `authorized_keys`. Le sens du transport est
tout ce qui compte.

**À installer sur la machine de surveillance** (une unité + un timer, cadence 5 min) :

1. `git fetch --depth 1 origin attestations` sur un clone local du dépôt public de `b` ;
2. extraire `courant/` dans un dossier **temporaire** ;
3. `python3 -B verifier_lot.py --lot <tmp> --clé-publique <ancre de b>` — le vérificateur voyage dans
   la branche (`verifier_lot.py` à sa racine), et **l'ancre est posée sur la machine de
   surveillance**, hors du lot. Sans ancre, il refuse : c'est délibéré (KE#130) ;
4. **si la vérification échoue, ou si le `git fetch` échoue : ne rien ingérer, et le DIRE.** Ne jamais
   écrire un fichier partiel, ne jamais rafraîchir un `ts`. L'état précédent vieillit alors tout seul
   et `service_muet` se déclenche — ce qui est exact. Écrire une sentinelle
   (`veilleur_b_indisponible`) plutôt qu'un dossier vide : une référence absente est une SENTINELLE,
   jamais une collection vide (KE#104) ;
5. si elle réussit, basculer atomiquement (`os.replace`) dans
   `/var/lib/spindex-surveillance/veilleur-b/`.

**Ce que je livre pour ça** : `outils/verifier_lot.py` (copié à chaque passage à la racine de la
branche). Il contrôle le domaine de signature, la clé contre l'ancre, la signature du manifeste
canonique, l'empreinte de **chaque** fichier, l'absence d'intrus, et le cardinal non nul. Il sort 0
ou 2, et **le verdict du veilleur n'entre pas dans son code de sortie** : « le lot est authentique »
et « le veilleur a trouvé quelque chose » sont deux questions, les confondre ferait lire une panne de
transport comme une alerte métier, ou l'inverse.

**L'ancre à poser** : la clé publique Ed25519 de `b`, créée hors ligne par l'utilisateur (README,
étape 2). Elle est publique — elle peut être écrite en clair dans le fichier de sources ou à côté.

> Pourquoi une signature, alors que `a` ne signe pas son battement : `a` écrit sur un disque que la
> surveillance lit directement, personne d'autre n'a pu l'écrire. Le battement de `b` traverse
> GitHub. Recopié tel quel, il ne prouverait rien : quiconque peut écrire dans le dépôt fabriquerait
> un battement vert pour un veilleur mort. La signature est la seule chose qui rétablit l'équivalent
> de « personne d'autre n'a pu l'écrire » — et encore : voir le point 5.

---

## 3. La cadence de `b` — correction demandée dans la famille `veilleur`

**Le problème, mesuré.** `b` bat toutes les 15 minutes (justification : README, « La cadence »).
Mais son `health.json` est écrit par le paquet **scellé**, et `battement.TACHES["passe"]` y porte
`période_s = 300` en dur — la cadence du timer systemd de `a`. `ecrire_health` en dérive
`silence_max_s = période + précision + délai_aléatoire + pire`, soit **431 s** relevés aujourd'hui
dans le `health.json` de `a`. La surveillance, qui lit cette borne dans le `health.json` de chaque
instance (BATTEMENT.md v1.2, et c'est la bonne règle), déclarera donc `b` **muette à chaque passage**.

**Ce que je n'ai pas fait, et pourquoi.** Réécrire le `health.json` après coup dans mon job serait
falsifier la déclaration du service. Le seul endroit correct est la famille scellée, et je n'y touche
pas.

**Correction demandée** (famille `backend/veilleur`, atelier suivant) : rendre la planification d'une
tâche **déclarable par instance**, par exemple

```
SPINDEX_VEILLEUR_PERIODE_PASSE_S='900'
SPINDEX_VEILLEUR_PRECISION_PASSE_S='60'
```

lus dans `.env` et injectés dans `TACHES` avant `ecrire_health`. La règle de BATTEMENT.md reste
intacte : la borne vient toujours du **service**, pas de la surveillance. Avec 900 s de période, 60 s
de précision et le pire cas observé, `b` publierait `silence_max_s ≈ 1 081 s`.

Le test qui compare `TACHES` aux unités systemd (`systemd-analyze calendar`) doit rester vrai pour
l'instance `a` : l'injection ne doit s'appliquer que si la variable est présente, et le test de
parité doit tourner sans elle.

**Et il ne faut PAS aller au-delà.** Un retard de GitHub au-delà de cette borne est un retard RÉEL :
`b` est en retard, et cela doit se voir. Élargir la borne pour faire taire l'alerte reviendrait à
régler le contrôle sur la panne du sujet (KE#121). La bonne réaction à `veilleur-b muet` est de
regarder l'onglet Actions, pas de relever le seuil.

---

## 4. Décision à prendre : les verdicts de `b` avant une signature du Safe

`regles.py:veilleurs()` compare les verdicts des deux instances par leur `empreinte_reproductible`
(P0 `veilleurs_divergents`) et alerte en P1 `veilleur_verdict_manquant` quand une instance a rendu un
verdict et que l'autre n'a rien rendu dans son `silence_max_s`.

**État actuel de `b`** : elle exécute la tâche planifiée `passe` (et les différentiels), **pas**
`avant-postweek` / `avant-opendraw`. Ces deux-là se lancent à la demande, avec un `--week`, juste
avant une signature du Safe. Je ne les ai pas câblées dans le workflow : ce serait un chemin non
éprouvé sur la voie la plus sensible du système, et je préfère un trou annoncé à un chemin non testé.

**Ce qu'il faut trancher** — deux options, pas trois :

- **(a) `b` rend aussi son feu vert.** Ajouter au workflow un `workflow_dispatch` portant `--week` et
  l'action, qui produit le verdict signé et le publie dans `courant/verdicts/`. Le Safe ne signe
  qu'avec **deux** feux verts portant la **même** `empreinte_reproductible`. C'est ce que la règle
  `veilleurs` suppose déjà, et c'est la seule lecture qui donne son sens à « deux instances ».
  Coût : un geste humain de plus avant chaque signature, et une attente de quelques minutes.
- **(b) `b` ne rend pas de feu vert**, et reste un témoin de surveillance continue. Il faut alors
  décider explicitement que `veilleur_verdict_manquant` **ne s'applique pas** à `b`, l'écrire dans la
  règle, et assumer que le quorum humain repose sur une seule instance au moment où il compte le plus.

Je recommande **(a)**, et je peux la câbler dans un atelier suivant, banc compris.

---

## 5. Ce que la surveillance ne doit PAS conclure de l'accord entre `a` et `b`

À écrire dans la règle, pas seulement ici :

- **Un désaccord ne dit pas laquelle des deux ment.** Il dit qu'il faut s'arrêter et regarder à la
  main. Ne pas écrire d'arbitrage automatique, sous aucune forme, y compris « deux contre un » le
  jour où il y aurait trois instances.
- **Un accord ne prouve pas l'indépendance.** Si les deux instances interrogent le même point d'entrée
  RPC, un nœud menteur les trompe ensemble. Le secret `SPINDEX_B_RPC_URL` doit pointer un fournisseur
  **différent** de celui de `a` ; c'est une consigne d'exploitation, et rien dans le code ne peut la
  vérifier. À vérifier à la main, et à re-vérifier après chaque rotation.
- **La clé de `b` est de moindre confiance que celle de `a`.** GitHub voit le secret et le
  propriétaire du compte peut le remplacer. Un feu vert de `b` **recoupe** celui de `a`, il ne le
  remplace pas. Si un jour `a` est indisponible et qu'on envisage de signer sur le seul feu vert de
  `b`, c'est une décision explicite à prendre à ce moment-là, pas une règle à écrire d'avance.
- **Les deux instances portent la même empreinte de sources** (`fbc8179779abd441…` aujourd'hui,
  publiée par les deux dans leur `health.json`). Une divergence d'empreinte doit être une alerte à
  part entière : elle veut dire que les deux ne font pas le même travail, donc que leur accord ne
  vaut rien. La surveillance a déjà `empreinte_divergente` par tâche contre `health.json` ; il
  manque la comparaison **entre instances**.

---

## 6. Divers, plus petit

- **Paramètres de chaîne dupliqués.** `config/chaine-46630.json` (adresse, bloc de déploiement, hash
  de la transaction, Multicall3) recopie ce que porte le `.env` de `a`. Un redéploiement oblige à
  mettre à jour les deux. Nommer une source canonique, ou accepter la duplication et l'inscrire dans
  la procédure de déploiement.
- **`SPINDEX_TABLES_BASE_URL` diffère volontairement.** `a` vise un dossier local de la machine du
  keeper ; `b` vise l'emplacement **publié** (`https://spindex.family/tables`). C'est une différence
  utile : `b` peut constater qu'une table n'est pas publiée là où le public la cherche, ce que `a` ne
  peut pas voir. À garder — et à ne pas lire comme une erreur de configuration.
- **La famille livre vite, et la copie doit suivre.** Pendant cet atelier, la release en service est
  passée de `c5b79cf2…` à `12517992…` (correctif KE#130 d'`verify_envelope`, entre autres) :
  `outils/resynchroniser.sh` a été relancé et la copie porte maintenant
  `f91addd8b65c6a61df63706146a69bcc7848fff1eec920a6555bdde906aab17d`, **la même empreinte que celle
  que `a` publie**. À intégrer à la procédure de livraison : une livraison de la famille `veilleur`
  n'est terminée que quand `b` a été resynchronisée, sinon les deux instances divergent sur le CODE
  et leur accord comme leur désaccord ne veulent plus rien dire.
