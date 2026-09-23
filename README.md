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
7. **Les actions tierces utilisées (`actions/checkout`, `actions/upload-artifact`) sont épinglées par
   étiquette majeure, pas par empreinte de commit.** Une étiquette peut être redirigée. Épingler les
   empreintes est le prochain geste (section « Entretien »).

---

## Ce que cette copie embarque

`veilleur/` est une copie du paquet scellé `backend/veilleur`, prise dans la **release EN SERVICE**
(`12517992…`, scellée le 2026-09-23 à 17:38 UTC), et **pas** dans l'arbre de travail de la famille.
C'est délibéré : `b` doit exécuter le code que `a` exécute, sinon une divergence entre les deux se
lirait comme un désaccord sur la chaîne alors que ce serait un désaccord sur le code.

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
`health.json` et dans chacun de ses battements, à chaque passe. Aujourd'hui :

```
f91addd8b65c6a61df63706146a69bcc7848fff1eec920a6555bdde906aab17d
```

Deux instances qui ne portent pas cette même empreinte n'exécutent pas le même code, et leur accord
— comme leur désaccord — ne voudrait rien dire.

S'ajoutent les contrôles de **couverture** (KE#111) : le sceau refuse un manifeste vide, refuse un
intrus sous `veilleur/` (un `.py` de plus à la racine **déplacerait** `empreinte_sources()`), et exige
que **tout** fichier exécuté ait été croisé avec le scellé de la famille.

---

## La cadence, et pourquoi ce n'est pas 5 minutes

`*/15`. Le minimum de GitHub est 5 minutes, mais ses exécutions sont approximatives : un `*/5` ne
serait pas « toutes les 5 minutes », ce serait « toutes les 5 à 25 minutes ».

Ce que `b` doit garantir n'est **pas** la règle des 5 minutes de publication d'une table — celle-là
appartient à `a`, sous systemd, sur une machine que nous tenons. `b` garantit qu'un **silence** ou un
**mensonge** de `a` se voie. L'échelle des choses qu'il doit voir est la semaine (`postWeek`), et les
échéances du contrat sont à J+30 et J+90 : un quart d'heure est sans commune mesure. En prime, `*/15`
donne trois fois plus de marge face aux retards de la plateforme et divise par trois la charge d'un
veilleur qui n'a pas de nœud à lui.

> ⚠️ **Point non résolu, à trancher par le coordinateur.** Le `health.json` que `b` publie est écrit
> par le paquet **scellé**, dont `battement.TACHES["passe"]["période_s"]` vaut 300 s en dur (la
> cadence du timer systemd). La surveillance en dérive `silence_max_s ≈ 431 s` et déclarera donc `b`
> **muet à chaque passage**. Détail et correction demandée : `DEMANDE-SURVEILLANCE.md`, point 3.

---

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
- `empreinte_sources` — c'est bien `fbc8179779abd441…`, la même que celle publiée par `a` ;
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

bash banc/preuves.sh  /tmp/banc-b /tmp/cle-banc.hex     # 6 situations, 12 contrôles, lecture seule
bash banc/cassures.sh /tmp/banc-b /tmp/cle-banc.hex     # 10 cassures : chaque garde est-elle portante ?
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
- **Épingler les actions par empreinte de commit** plutôt que par étiquette majeure
  (`actions/checkout@<sha>`), pour fermer la limite n°7.
- **La branche `attestations` grossit** d'environ vingt kilo-octets par passage. La remettre à plat
  est un geste **humain**, une fois par an, jamais une poussée en force automatique — elle effacerait
  l'histoire que la branche existe pour garder.
- **Les workflows planifiés sont désactivés après 60 jours sans activité** sur le dépôt. Les commits
  du job n'y suffisent pas toujours : le vérifier à chaque entretien.
- **Si la clé de `b` doit être remplacée** : créer la nouvelle (étape 2), remplacer le secret (étape
  3), **puis** diffuser la nouvelle ancre. Tant que l'ancienne ancre est posée quelque part, les lots
  neufs y seront refusés — bruyamment, ce qui est le comportement voulu.
