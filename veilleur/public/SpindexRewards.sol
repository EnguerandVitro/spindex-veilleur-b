// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DrandQuicknetVerifier} from "./DrandQuicknetVerifier.sol";

/// @dev ERC-20 minimal lu par le contrat (USDG 6 déc., $SPDX 18 déc.).
interface IERC20Min {
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @title  SPINDEX, SpindexRewards v1 : Lock, rakeback, parrainage, burn, Stock Draw (PROTOTYPE, non audité).
/// @notice Spécification : contracts/rewards/REWARDS_SPEC.md §2 à §7 ; reconnaissance : rewards/rapports/reconnaissance.md.
///         Le Vault et SpinTickets sont FIGÉS : ce contrat ne leur demande rien et ne les modifie pas.
///         Il ne fait que GARDER des fonds, VÉRIFIER une preuve et PAYER une fois.
/// @dev    Unités : USDG 6 déc. ; $SPDX 18 déc. (mesuré sur 44/44 tokens Virtuals de la 4663) ; poids du tirage sans
///         unité (entiers, pavage exact de [0, totalWeight) garanti côté indexeur).
///
///         CE QUE LE CONTRAT NE FAIT PAS : aucun swap (même règle que le Vault), aucun calcul de rakeback
///         (l'indexeur le fait hors chaîne et publie une empreinte merkle), aucun point de saison, aucune
///         lecture de prix $SPDX (les seuils de rang sont en TOKENS, figés au déploiement — décision 2026-09-20).
///
///         CONVENTION MERKLE (reconnaissance §5, identique pour les deux arbres) :
///           feuille = keccak256(bytes.concat(keccak256(abi.encode(...))))   ← DOUBLE hachage, abi.encode
///           nœud    = keccak256(min(a,b) ‖ max(a,b))                        ← paires triées
///         Côté indexeur : pas de duplication du nœud impair, feuilles triées, `leafCount` publié avec la racine.
///
///         RISQUE PORTÉ, MESURÉ (reconnaissance §4) : `owner()` du token $SPDX est et restera l'EOA Virtuals
///         `0xe220329659d41b2a9f26e83816b424bdacf62567` (aucun code : une clé privée). Elle peut inscrire ce
///         contrat en liste noire (les $SPDX stakés deviennent intransférables) ou le déclarer « pool »
///         (`addLiquidityPool`) puis taxer jusqu'à 100 % (`setProjectTaxRates`). Atténuations gratuites mises en
///         œuvre ici : mesure du montant reçu au `stake` (refus si ≠), crédit du delta réellement transféré à la
///         sortie (jamais de blocage), et burn de sortie différé si le token refuse le `burn` (§ `unstake`).
contract SpindexRewards {
    // ================================================================== constantes

    uint256 internal constant BPS = 10_000;

    /// @notice §2 : 10 % du montant sorti sont BRÛLÉS (pas envoyés à une adresse morte : `burn(uint256)` du token
    ///         d'agent Virtuals est public et réduit réellement `totalSupply` — mesuré, reconnaissance §1.2).
    uint256 public constant EXIT_BURN_BPS = 1_000;

    /// @notice §2, boost de fidélité : ×1 au départ, +1/30 par jour, plafonné à ×3 à 60 jours.
    ///         Échelle fixe 1e18 : BOOST_ONE = ×1, BOOST_MAX = ×3.
    uint256 public constant BOOST_ONE = 1e18;
    uint256 public constant BOOST_MAX = 3e18;
    /// @dev +BOOST_ONE par tranche de BOOST_RAMP ; l'ancienneté prise en compte est plafonnée à BOOST_CAP_ELAPSED.
    ///      BOOST_ONE + BOOST_ONE × 60 j / 30 j = 3e18 = BOOST_MAX (vérifié au constructeur).
    uint256 public constant BOOST_RAMP = 30 days;
    uint256 public constant BOOST_CAP_ELAPSED = 60 days;

    /// @notice §3 : une semaine non réclamée est balayable par le Safe au bout de 90 jours.
    uint256 public constant CLAIM_WINDOW = 90 days;
    /// @notice §6 : un prix non réclamé retourne au Safe au bout de 30 jours.
    uint256 public constant PRIZE_WINDOW = 30 days;

    /// @notice §6 : bornes de DELTA. Plancher **30 s** (v5, §23/P0-2 jambe (iii)) — plus strict que le MIN_DELTA
    ///         de SpindexSpins (8 s), même règle `roundFor` / `publishTime`.
    /// @dev    **Ce plancher est une MARGE MESURÉE, plus un choix de confort.** `roundFor` ne garantit
    ///         « l'engagement précède le hasard » que tant que le retard de `block.timestamp` sur l'heure réelle
    ///         reste SOUS DELTA. Mesure du projet sur la 4663 (`measurements/blockts-24h.jsonl`, **159 908
    ///         blocs / 24,0 h**) : p50 1,28 s · p99 3,13 s · p99,99 4,60 s · **max 5,69 s**. À 10 s il restait
    ///         ~3,5 s de marge une fois retirée la latence de publication drand (0,21–0,74 s) ; à 30 s il en
    ///         reste ~23,5 s, soit plus de 4× le pire retard observé. Sur un tirage HEBDOMADAIRE, attendre ne
    ///         coûte rien : c'est la seule raison pour laquelle ce plancher peut être aussi haut.
    ///         Ce n'est qu'une défense en PROFONDEUR : la borne réelle est `maxPublishedRound + 2` (`openDraw`),
    ///         qui ne dépend d'aucune hypothèse sur l'horloge de la chaîne.
    uint256 public constant MIN_DELTA = 30;
    uint256 public constant MAX_DELTA = 60;
    /// @notice §6 : bornes du plafond de gaz de la vérification drand (mêmes que SpindexSpins ; une signature
    ///         invalide fait brûler au précompilé BLS TOUT le gaz transmis).
    uint256 public constant MIN_VERIFY_GAS = 150_000;
    uint256 public constant MAX_VERIFY_GAS = 2_000_000;

    /// @notice §21/P2-1 : plafond de gaz du `burn(uint256)` du token. Le `strandedBurn` couvre « révoque » et
    ///         « rien détruit », **pas** « consomme tout le gaz » : sans plafond, le chemin de SORTIE D'UN JOUEUR
    ///         transmet tout le gaz restant à un contrat que nous ne contrôlons pas (mesuré : 64 056 gaz sur une
    ///         sortie saine, **2 560 976 au plancher** contre un `burn` gourmand, ×40).
    /// @dev    **Volontairement généreux, et `constant` plutôt que paramètre de construction.** Généreux : un
    ///         plafond trop court ne se répare PAS (même raisonnement que `VERIFY_GAS` en §20) — il ferait
    ///         échouer tous les burns de sortie (différés à vie) et révoquer le burn hebdomadaire, sur un
    ///         contrat qui détient le stake de tout le monde. 500 000 laisse ~10× le coût d'un `burn` ERC-20
    ///         ordinaire tout en divisant par 5 le pire cas mesuré. `constant` : le rendre configurable
    ///         ajouterait un argument de construction, donc un rejeu complet des ateliers 1/3/4, pour une
    ///         valeur dont aucune mesure ne suggère qu'elle doive varier.
    uint256 public constant BURN_GAS = 500_000;

    /// @notice $SPDX a 18 décimales sur 44/44 tokens d'agent mesurés (reconnaissance §1.2) : contrôlé à
    ///         `setSpdxToken`, parce que les seuils de rang sont exprimés dans cette unité.
    uint8 public constant SPDX_DECIMALS = 18;

    /// @dev sélecteur de `burn(uint256)` du token d'agent Virtuals.
    bytes4 private constant SEL_BURN = bytes4(keccak256("burn(uint256)"));

    // ================================================================== types

    /// @notice §2 : rangs. Le taux de rakeback n'est PAS utilisé par le contrat (calcul hors chaîne) ; il est
    ///         exposé pour que l'interface et l'indexeur lisent la même source.
    enum Rank {
        Penny,
        Small,
        Mid,
        Large,
        Mega
    }

    /// @dev un joueur tient dans UN emplacement (128 + 64 = 192 bits).
    ///      amount : $SPDX stakés en unités brutes (offre = 1e27 ≪ 2^128).
    ///      anchor : ancre du boost (timestamp) ; 0 quand le joueur n'a rien staké.
    struct Lock {
        uint128 amount;
        uint64 anchor;
    }

    /// @dev une semaine de rakeback / rev-share.
    struct Week {
        bytes32 root; // 0 = pas encore publiée
        uint128 funded; // USDG versés par le Safe
        uint128 claimed; // USDG déjà payés aux joueurs
        uint64 fundedAt; // premier versement
        uint64 postedAt; // publication de la racine
        uint32 leafCount; // nombre de feuilles annoncé (reconnaissance §5)
        bool swept;
    }

    /// @dev un Stock Draw hebdomadaire.
    struct Draw {
        bytes32 weightsRoot; // 0 = pas ouvert
        bytes32 randomness; // 0 = pas réglé
        address prizeToken;
        uint40 round; // round drand figé à l'OUVERTURE
        uint64 openedAt;
        uint64 settledAt;
        uint128 totalWeight;
        uint128 prizeAmount;
        uint128 winningX; // randomness mod totalWeight
        bool claimed;
        bool returned;
    }

    // ================================================================== état

    DrandQuicknetVerifier public immutable verifier;
    /// @notice USDG (6 déc.) : enveloppes hebdomadaires du rakeback et du rev-share.
    address public immutable usdg;
    /// @notice §6 : marge (s) entre l'ouverture du tirage et le round drand lié. IMMUABLE.
    uint256 public immutable DELTA;
    /// @notice plafond de gaz de `verifyUncompressed`, IMMUABLE (un propriétaire qui pourrait le baisser
    ///         empêcherait tout règlement de tirage).
    uint256 public immutable VERIFY_GAS;
    /// @notice calendrier drand quicknet, RELU du vérificateur au déploiement (aucune constante recopiée).
    uint256 public immutable GENESIS;
    uint256 public immutable PERIOD;

    /// @notice §2, seuils de rang en TOKENS $SPDX (18 déc.), IMMUABLES, strictement croissants.
    ///         Le rang se lit sur le STAKE EFFECTIF (montant × boost).
    uint256 public immutable RANK_SMALL;
    uint256 public immutable RANK_MID;
    uint256 public immutable RANK_LARGE;
    uint256 public immutable RANK_MEGA;

    /// @notice §2 : adresse du token $SPDX. Inconnue avant `preLaunch` (reconnaissance §2.2) ⇒ posée UNE fois par
    ///         le Safe, puis verrouillée définitivement. SEULE entorse à l'immuabilité de ce contrat.
    address public spdx;

    address public owner;
    address public pendingOwner;
    address public keeper;
    /// @notice §7 : pause d'urgence. N'empêche JAMAIS `unstake`, ni `claim` d'une semaine déjà publiée, ni
    ///         `settleDraw` / `claimPrize` d'un tirage déjà ouvert (l'engagement est antérieur à la pause).
    bool public paused;

    /// @notice $SPDX stakés par les joueurs (passif du contrat : jamais brûlables par le keeper).
    uint256 public totalStaked;
    /// @notice $SPDX du burn de sortie qui N'ONT PAS ÉTÉ DÉTRUITS (token en liste noire, `burn` révoqué, `burn`
    ///         partiel…) : réservés, rebrûlables par `flushExitBurn`. Ne servent jamais d'assiette au burn
    ///         hebdomadaire. N'inscrit QUE le reliquat : jamais une part déjà détruite (§21, P1-1).
    uint256 public strandedBurn;
    /// @notice USDG des semaines versés et pas encore payés ni balayés (passif du contrat).
    uint256 public usdgReserved;
    /// @notice dotations de tirage déjà engagées, par token (passif du contrat).
    mapping(address => uint256) public prizeReserved;

    mapping(address => Lock) private _locks;
    /// @notice §4 : registre de parrainage. Se fixe UNE fois, ne change jamais.
    mapping(address => address) public referrerOf;

    mapping(uint256 => Week) private _weeks;
    /// @notice un joueur ne peut être payé qu'une fois par semaine.
    mapping(uint256 => mapping(address => bool)) public claimedBy;

    /// @notice §5 : enveloppe USDG du burn déclarée par le Safe pour la semaine, et somme des `usdgSpent` déclarés.
    mapping(uint256 => uint256) public burnFunded;
    mapping(uint256 => uint256) public burnSpent;
    /// @notice $SPDX réellement détruits par le burn hebdomadaire de la semaine.
    mapping(uint256 => uint256) public burnedTokens;

    mapping(uint256 => Draw) private _draws;

    /// @notice §6 : plus grand round drand dont une signature a été VÉRIFIÉE ICI. **Monotone.** C'est l'horloge
    ///         que le séquenceur ne contrôle pas : un round ne peut y entrer qu'accompagné d'une signature BLS
    ///         valide, donc `maxPublishedRound` ne peut jamais dépasser la tête réelle de drand.
    ///         Transplanté de `SpindexSpins` (`maxPublishedRound` + plancher `+2`), §23/P0-2.
    uint64 public maxPublishedRound;

    bool private transient _locked;

    // ================================================================== événements

    event SpdxTokenSet(address indexed token);
    event Staked(address indexed player, uint256 amount, uint256 newAmount, uint64 anchor);
    event Unstaked(
        address indexed player, uint256 amount, uint256 burned, uint256 sent, uint256 remaining
    );
    event ExitBurnDeferred(address indexed player, uint256 amount, uint256 strandedTotal);
    event ExitBurnFlushed(uint256 amount);
    /// @notice le `burn` du token a détruit un montant DIFFÉRENT de celui demandé (partiel ou excédentaire).
    ///         Jamais émis pour « rien détruit » : ce cas est déjà porté par `ExitBurnDeferred` / `BurnFailed`.
    event BurnMismatch(uint256 requested, uint256 burned);
    event BoostHalved(address indexed player, uint64 previousAnchor, uint64 newAnchor);
    event ReferrerSet(address indexed player, address indexed referrer);
    event WeekFunded(uint256 indexed weekId, uint256 usdgAmount, uint256 funded);
    event WeekPosted(uint256 indexed weekId, bytes32 root, uint256 totalUsdg, uint32 leafCount);
    event Claimed(uint256 indexed weekId, address indexed player, uint256 rakebackUsdg, uint256 revshareUsdg);
    event WeekSwept(uint256 indexed weekId, uint256 residual);
    event BurnFunded(uint256 indexed weekId, uint256 usdgAmount, uint256 funded);
    event Burned(uint256 indexed weekId, uint256 amount, uint256 usdgSpent, uint256 newTotalSupply);
    event DrawOpened(
        uint256 indexed weekId,
        bytes32 weightsRoot,
        uint256 totalWeight,
        address prizeToken,
        uint256 prizeAmount,
        uint64 round
    );
    event DrawSettled(uint256 indexed weekId, uint64 round, bytes32 randomness, uint256 winningX);
    /// @notice un round drand a été prouvé ici. Sert de preuve de vie de l'horloge ET de piste de surveillance :
    ///         un veilleur compare `round` à la tête drand réelle, donc une preuve périmée est VISIBLE (KE#105).
    event RoundPublished(uint64 indexed round, bytes32 randomness);
    event PrizeClaimed(uint256 indexed weekId, address indexed winner, address prizeToken, uint256 sent);
    event PrizeReturned(uint256 indexed weekId, address prizeToken, uint256 amount);
    event PauseSet(bool paused);
    event KeeperSet(address indexed keeper);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ================================================================== erreurs

    error BadConfig();
    error NotOwner();
    error NotPendingOwner();
    error NotKeeper();
    error NotKeeperNorOwner();
    error Reentrancy();
    error IsPaused();
    error TokenNotSet();
    error TokenAlreadySet();
    error BadDecimals(uint8 got);
    error BadAmount();
    error InsufficientStake(uint256 staked);
    /// @notice §2 : le `stake` a crédité moins que `amount` (taxe activée par l'EOA Virtuals). On REFUSE d'entrer
    ///         dans un état faux plutôt que de créditer un stake effectif qui mentirait sur le rang.
    error FeeOnTransferNotSupported(uint256 sent, uint256 received);
    error TransferFailed();
    error BurnFailed();
    error NothingStranded();
    error InsufficientFreeBalance(uint256 free, uint256 needed);
    error ReferrerAlreadySet();
    error BadReferrer();
    error ReferralCycle();
    error WeekNotFunded();
    error WeekAlreadyPosted();
    error WeekNotPosted();
    error WeekAlreadySwept();
    error BadRoot();
    error EnvelopeTooSmall(uint256 totalUsdg, uint256 funded);
    error AlreadyClaimed();
    error BadProof();
    error ClaimExceedsEnvelope(uint256 claimed, uint256 funded);
    error SweepTooEarly(uint256 readyAt);
    error BurnBudgetExceeded(uint256 spent, uint256 funded);
    error DrawAlreadyOpen();
    error DrawNotOpen();
    error DrawAlreadySettled();
    error DrawNotSettled();
    error PrizeAlreadyClaimed();
    error PrizeAlreadyReturned();
    error BadInterval();
    error NotTheWinner(uint256 x);
    error InvalidBeacon();
    error BadRound();
    error ReturnTooEarly(uint256 readyAt);

    // ================================================================== modificateurs

    /// @dev verrou en stockage transitoire (EIP-1153) : couvre toute fonction qui fait un appel externe non statique.
    modifier nonReentrant() {
        if (_locked) revert Reentrancy();
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyKeeper() {
        if (msg.sender != keeper) revert NotKeeper(); // keeper == 0 : personne (msg.sender ≠ 0)
        _;
    }

    // v5 : le modificateur `onlyKeeperOrOwner` a été SUPPRIMÉ avec `openDraw` (§23/P0-1 a), son unique
    // utilisateur. Un modificateur de droits sans appelant est une porte qu'il suffit de rebrancher : on ne le
    // laisse pas « au cas où ». L'erreur `NotKeeperNorOwner` reste déclarée le temps que les ateliers 1 et 3
    // migrent leurs tables de refus — elle n'est plus révélée par aucun chemin du contrat.

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    // ================================================================== construction

    /// @param verifier_  `DrandQuicknetVerifier` déployé (sans état, sans propriétaire)
    /// @param usdg_      USDG (6 déc.)
    /// @param owner_     Safe multisig
    /// @param keeper_    keeper du burn et du tirage (0 possible : posé ensuite par `setKeeper`)
    /// @param delta      marge (s) avant le round drand lié à un tirage, ∈ [MIN_DELTA, MAX_DELTA]
    /// @param verifyGas  plafond de gaz de `verifyUncompressed`
    /// @param thresholds seuils de rang EN TOKENS $SPDX (Small, Mid, Large, Mega), strictement croissants, > 0
    /// @dev    L'adresse de $SPDX n'existe pas avant `preLaunch` (reconnaissance §2.2) : elle est posée ensuite,
    ///         UNE fois, par `setSpdxToken`. Ce contrat doit être déployé AVANT `preLaunch`.
    constructor(
        DrandQuicknetVerifier verifier_,
        address usdg_,
        address owner_,
        address keeper_,
        uint256 delta,
        uint256 verifyGas,
        uint256[4] memory thresholds
    ) {
        if (address(verifier_).code.length == 0 || usdg_.code.length == 0) revert BadConfig();
        if (owner_ == address(0)) revert BadConfig();
        if (delta < MIN_DELTA || delta > MAX_DELTA) revert BadConfig();
        if (verifyGas < MIN_VERIFY_GAS || verifyGas > MAX_VERIFY_GAS) revert BadConfig();
        if (thresholds[0] == 0) revert BadConfig();
        if (thresholds[1] <= thresholds[0] || thresholds[2] <= thresholds[1] || thresholds[3] <= thresholds[2]) {
            revert BadConfig();
        }
        // le plafond du boost doit être exactement ×3 à 60 jours (cohérence des deux constantes publiées)
        if (BOOST_ONE + BOOST_ONE * BOOST_CAP_ELAPSED / BOOST_RAMP != BOOST_MAX) revert BadConfig();

        verifier = verifier_;
        usdg = usdg_;
        DELTA = delta;
        VERIFY_GAS = verifyGas;
        GENESIS = verifier_.GENESIS_TIME();
        PERIOD = verifier_.PERIOD();
        if (GENESIS == 0 || PERIOD == 0) revert BadConfig();
        RANK_SMALL = thresholds[0];
        RANK_MID = thresholds[1];
        RANK_LARGE = thresholds[2];
        RANK_MEGA = thresholds[3];
        owner = owner_;
        keeper = keeper_;
        emit OwnershipTransferred(address(0), owner_);
        emit KeeperSet(keeper_);
    }

    /// @notice §2 : pose l'adresse de $SPDX. UNE SEULE FOIS, par le Safe, puis verrouillée définitivement.
    /// @dev    Contrôles : code non vide (un clone EIP-1167 en porte 45 octets) et 18 décimales (mesuré 18 sur
    ///         44/44 tokens d'agent) — les seuils de rang sont exprimés dans cette unité, une erreur ici les
    ///         décalerait d'un facteur 10^k sans recours possible.
    function setSpdxToken(address token) external onlyOwner {
        if (spdx != address(0)) revert TokenAlreadySet();
        if (token == address(0) || token.code.length == 0 || token == usdg) revert BadConfig();
        uint8 d = IERC20Min(token).decimals();
        if (d != SPDX_DECIMALS) revert BadDecimals(d);
        if (IERC20Min(token).totalSupply() == 0) revert BadConfig();
        spdx = token;
        emit SpdxTokenSet(token);
    }

    // ================================================================== §2 Lock

    /// @notice stake `amount` $SPDX. Mesure le montant RÉELLEMENT reçu et REFUSE si le delta ≠ `amount`
    ///         (reconnaissance §4 : `addLiquidityPool(ce contrat)` + `setProjectTaxRates` sont des pouvoirs actifs
    ///         d'une EOA tierce ; créditer moins ferait diverger le stake effectif des rangs annoncés).
    ///         Ajout de stake : l'ancre du boost devient la MOYENNE PONDÉRÉE des ancres (ajouter dilue le boost,
    ///         sans le perdre ; l'ancre ne peut que se rapprocher de maintenant, donc le boost ne monte jamais).
    function stake(uint256 amount) external nonReentrant whenNotPaused {
        address token = spdx;
        if (token == address(0)) revert TokenNotSet();
        if (amount == 0) revert BadAmount();

        uint256 received = _pullMeasured(token, msg.sender, amount);
        if (received != amount) revert FeeOnTransferNotSupported(amount, received);

        Lock memory l = _locks[msg.sender];
        uint256 newAmount = uint256(l.amount) + amount;
        if (newAmount > type(uint128).max) revert BadAmount();

        uint64 anchor;
        if (l.amount == 0) {
            anchor = uint64(block.timestamp);
        } else {
            // §11.4 : l'ancienneté de l'ancre est PLAFONNÉE à 60 jours AVANT la moyenne pondérée. Lecture stricte :
            // au-delà du plafond, l'ancienneté n'apporte plus rien au boost, elle ne doit donc pas non plus servir de
            // réserve pour diluer un gros ajout. Les deux lectures coïncident sous 60 jours.
            uint64 oldAnchor = l.anchor;
            uint64 floorAnchor =
                block.timestamp > BOOST_CAP_ELAPSED ? uint64(block.timestamp - BOOST_CAP_ELAPSED) : uint64(0);
            if (oldAnchor < floorAnchor) oldAnchor = floorAnchor;
            // (oldAmount × oldAnchor + amount × now) / newAmount — bornes : 2^128 × 2^64 = 2^192, pas de débordement
            anchor = uint64((uint256(l.amount) * uint256(oldAnchor) + amount * block.timestamp) / newAmount);
        }
        _locks[msg.sender] = Lock(uint128(newAmount), anchor);
        totalStaked += amount;
        emit Staked(msg.sender, amount, newAmount, anchor);
    }

    /// @notice sort `amount` $SPDX : 10 % BRÛLÉS, 90 % rendus. Le boost du reste retombe à ×1 (sortir coûte la
    ///         fidélité, pas seulement les 10 %). JAMAIS bloqué par la pause (invariant §8.1).
    /// @dev    Le montant rendu est crédité au DELTA RÉELLEMENT TRANSFÉRÉ (`sent` dans l'événement) : si une taxe
    ///         apparaissait, on ne bloque pas la sortie. Si le `burn` du token échoue (liste noire, adaptateur de
    ///         frais remplacé…), le RELIQUAT NON DÉTRUIT est MIS DE CÔTÉ (`strandedBurn`, rebrûlable par
    ///         `flushExitBurn`) au lieu de faire échouer la sortie — jamais la totalité des 10 % quand une part
    ///         est déjà partie (§21, P1-1).
    function unstake(uint256 amount) external nonReentrant {
        address token = spdx;
        if (token == address(0)) revert TokenNotSet();
        Lock memory l = _locks[msg.sender];
        if (amount == 0) revert BadAmount();
        if (amount > l.amount) revert InsufficientStake(l.amount);

        uint256 remaining = uint256(l.amount) - amount;
        // effets AVANT interactions ; sortie partielle ⇒ ancre = maintenant ⇒ boost exactement ×1
        _locks[msg.sender] =
            Lock(uint128(remaining), remaining == 0 ? uint64(0) : uint64(block.timestamp));
        totalStaked -= amount;

        uint256 burnAmount = amount * EXIT_BURN_BPS / BPS;
        uint256 payout = amount - burnAmount;

        if (burnAmount != 0) {
            // §21/P1-1 : on ne diffère que le RELIQUAT. Ce qui est déjà détruit ne doit pas être réinscrit au
            // passif — sinon le Lock doit plus qu'il ne détient, `freeBalance` écrase le trou à 0, et le
            // `flushExitBurn` suivant détruit la différence SUR LE STAKE DES AUTRES.
            // Sur-destruction (`burned > burnAmount`) ⇒ reliquat nul : le trop-détruit est irrécupérable, mais
            // il n'est pas ABSORBÉ EN SILENCE — `BurnMismatch` le publie (KE#105).
            uint256 burned = _tryBurnSpdx(token, burnAmount);
            if (burned < burnAmount) {
                uint256 shortfall = burnAmount - burned;
                uint256 stranded = strandedBurn + shortfall;
                strandedBurn = stranded;
                emit ExitBurnDeferred(msg.sender, shortfall, stranded);
            }
        }
        uint256 sent = _sendMeasured(token, msg.sender, payout);
        emit Unstaked(msg.sender, amount, burnAmount, sent, remaining);
    }

    /// @notice rebrûle les 10 % de sortie dont le `burn` avait échoué. Ouvert à tous (ne déplace rien vers personne).
    function flushExitBurn() external nonReentrant {
        uint256 amount = strandedBurn;
        if (amount == 0) revert NothingStranded();
        address token = spdx;
        if (token == address(0)) revert TokenNotSet();
        // §21/P1-1 : on ne solde QUE ce qui a réellement été détruit. Une destruction partielle est un progrès
        // réel (les tokens sont partis) : la révoquer ne rendrait rien et laisserait le passif gravé pour
        // toujours, donc on garde le reliquat inscrit et l'appel suivant le vide. `ExitBurnFlushed` porte le
        // montant DÉTRUIT, pas le montant visé (c'est lui qui alimente la ligne « détruit » de §19).
        uint256 burned = _tryBurnSpdx(token, amount);
        if (burned == 0) revert BurnFailed();
        strandedBurn = burned >= amount ? 0 : amount - burned;
        emit ExitBurnFlushed(burned);
    }

    // ================================================================== §3 semaines publiées

    /// @notice le Safe dépose l'enveloppe USDG de la semaine (rakeback + rev-share). Cumulable.
    function fundWeek(uint256 weekId, uint256 usdgAmount) external nonReentrant onlyOwner {
        if (usdgAmount == 0) revert BadAmount();
        Week storage w = _weeks[weekId];
        if (w.swept) revert WeekAlreadySwept();
        uint256 received = _pullMeasured(usdg, msg.sender, usdgAmount);
        if (received != usdgAmount) revert FeeOnTransferNotSupported(usdgAmount, received);
        uint256 funded = uint256(w.funded) + usdgAmount;
        if (funded > type(uint128).max) revert BadAmount();
        w.funded = uint128(funded);
        if (w.fundedAt == 0) w.fundedAt = uint64(block.timestamp);
        usdgReserved += usdgAmount;
        emit WeekFunded(weekId, usdgAmount, funded);
    }

    /// @notice le Safe publie l'empreinte de la semaine. UNE SEULE FOIS : personne ne peut réécrire une racine.
    /// @param  totalUsdg somme des feuilles annoncée par l'indexeur. EXIGENCE (§16) : `totalUsdg ≤ funded(weekId)`
    ///         au moment de la publication — on ne publie jamais une promesse que l'enveloppe ne couvre pas.
    ///         C'est une borne de PUBLICATION ; la borne des PAIEMENTS reste `funded` (contrôlée à chaque `claim`,
    ///         et `funded` peut encore monter après la publication par un `fundWeek` complémentaire).
    /// @param  leafCount nombre de feuilles (reconnaissance §5 : publié à côté de la racine pour qu'un tiers
    ///         puisse reconstruire l'arbre et prouver qu'il n'y a pas de feuille cachée).
    function postWeek(uint256 weekId, bytes32 root, uint256 totalUsdg, uint32 leafCount) external onlyOwner {
        if (root == bytes32(0)) revert BadRoot();
        Week storage w = _weeks[weekId];
        if (w.root != bytes32(0)) revert WeekAlreadyPosted();
        if (w.swept) revert WeekAlreadySwept();
        if (w.fundedAt == 0) revert WeekNotFunded();
        if (totalUsdg > w.funded) revert EnvelopeTooSmall(totalUsdg, w.funded);
        w.root = root;
        w.postedAt = uint64(block.timestamp);
        w.leafCount = leafCount;
        emit WeekPosted(weekId, root, totalUsdg, leafCount);
    }

    /// @notice le joueur réclame sa feuille. UNE SEULE FOIS par semaine, pour le montant EXACT de la feuille,
    ///         jamais au-delà de l'enveloppe versée. JAMAIS bloqué par la pause (invariant §8.2).
    /// @dev    feuille = keccak256(bytes.concat(keccak256(abi.encode(address player, uint256 weekId,
    ///         uint256 rakebackUsdg, uint256 revshareUsdg)))) — convention de reconnaissance §5.
    ///         La RÉCOLTE DU RAKEBACK divise le MULTIPLICATEUR de boost par deux, jamais sous ×1 (§15 : ×3 → ×1,5) ;
    ///         le rev-share, lui, ne touche pas au boost (§3).
    function claim(uint256 weekId, uint256 rakebackUsdg, uint256 revshareUsdg, bytes32[] calldata proof)
        external
        nonReentrant
    {
        Week storage w = _weeks[weekId];
        bytes32 root = w.root;
        if (root == bytes32(0)) revert WeekNotPosted();
        if (w.swept) revert WeekAlreadySwept();
        if (claimedBy[weekId][msg.sender]) revert AlreadyClaimed();

        uint256 amount = rakebackUsdg + revshareUsdg;
        if (amount == 0) revert BadAmount();

        bytes32 leaf =
            keccak256(bytes.concat(keccak256(abi.encode(msg.sender, weekId, rakebackUsdg, revshareUsdg))));
        if (!_verify(proof, root, leaf)) revert BadProof();

        uint256 claimed_ = uint256(w.claimed) + amount;
        if (claimed_ > w.funded) revert ClaimExceedsEnvelope(claimed_, w.funded);

        claimedBy[weekId][msg.sender] = true;
        w.claimed = uint128(claimed_);
        usdgReserved -= amount;

        if (rakebackUsdg != 0) _halveBoost(msg.sender);
        emit Claimed(weekId, msg.sender, rakebackUsdg, revshareUsdg);
        _send(usdg, msg.sender, amount);
    }

    /// @notice le Safe récupère le reliquat d'une semaine, 90 jours après sa publication (ou, si elle n'a jamais
    ///         été publiée, 90 jours après son premier versement — sinon l'enveloppe serait piégée à vie).
    function sweepWeek(uint256 weekId) external nonReentrant onlyOwner {
        Week storage w = _weeks[weekId];
        if (w.fundedAt == 0) revert WeekNotFunded();
        if (w.swept) revert WeekAlreadySwept();
        uint256 readyAt = uint256(w.postedAt != 0 ? w.postedAt : w.fundedAt) + CLAIM_WINDOW;
        if (block.timestamp < readyAt) revert SweepTooEarly(readyAt);
        uint256 residual = uint256(w.funded) - uint256(w.claimed);
        w.swept = true;
        usdgReserved -= residual;
        emit WeekSwept(weekId, residual);
        if (residual != 0) _send(usdg, owner, residual);
    }

    // ================================================================== §4 parrainage

    /// @notice fixe son parrain. UNE SEULE FOIS, jamais soi-même, jamais un cycle direct (A→B→A).
    /// @dev    L'éligibilité « avant le premier spin » est prouvée hors chaîne par l'indexeur (§4) : le contrat
    ///         ne garde QUE le lien et la règle « une seule fois ».
    function setReferrer(address referrer) external whenNotPaused {
        if (referrerOf[msg.sender] != address(0)) revert ReferrerAlreadySet();
        if (referrer == address(0) || referrer == msg.sender) revert BadReferrer();
        if (referrerOf[referrer] == msg.sender) revert ReferralCycle();
        referrerOf[msg.sender] = referrer;
        emit ReferrerSet(msg.sender, referrer);
    }

    // ================================================================== §5 burn hebdomadaire

    /// @notice le Safe DÉCLARE l'enveloppe USDG du burn de la semaine. Cumulable.
    /// @dev    ⚠️ Déclaration seule, AUCUN transfert d'USDG : le keeper achète HORS contrat (le contrat ne swappe
    ///         pas, §1) avec des USDG que le Safe lui verse directement. Cette borne empêche seulement un
    ///         `usdgSpent` déclaratif de mentir AU-DELÀ de l'enveloppe (§5, invariant §10.9). Point soumis au
    ///         coordinateur (rapport, question 3).
    function fundBurn(uint256 weekId, uint256 usdgAmount) external onlyOwner {
        if (usdgAmount == 0) revert BadAmount();
        uint256 funded = burnFunded[weekId] + usdgAmount;
        burnFunded[weekId] = funded;
        emit BurnFunded(weekId, usdgAmount, funded);
    }

    /// @notice le keeper a acheté les $SPDX hors chaîne et les a envoyés ici : le contrat les DÉTRUIT.
    /// @dev    Preuve on-chain : `totalSupply` doit baisser EXACTEMENT de `amount`, sinon on révèle. L'assiette est
    ///         le solde LIBRE (solde du contrat − stakes des joueurs − burns de sortie différés − dotations de
    ///         tirage) : le burn hebdomadaire ne mord pas sur les $SPDX stakés.
    ///         ⚠️ **Cette garantie est CONDITIONNELLE à la sincérité de `balanceOf` du token** (§21, P2-2) : le
    ///         même contrat rend le solde ET exécute la destruction. Un token qui SUR-DÉCLARE le solde du Lock
    ///         fait passer le contrôle `_free(token) >= amount` et laisse détruire des jetons STAKÉS — et la
    ///         preuve `totalSupply` reste satisfaite, puisqu'elle porte sur ce que le token a bien détruit.
    ///         Mesuré (atelier sécurité) : solde sincère ⇒ `InsufficientFreeBalance(0, 900e18)` ; solde menteur
    ///         ⇒ le MÊME appel détruit 900 des 1 000 $SPDX stakés. Aucun correctif indépendant n'existe ici :
    ///         tout contrôle d'assiette passe par `balanceOf`. La borne est donc « le contrat ne mord pas sur
    ///         les stakes TANT QUE le token dit la vérité sur son solde » — la confiance dans l'émetteur du
    ///         token est un risque assumé de §7, pas une garantie du code.
    function burn(uint256 weekId, uint256 amount, uint256 usdgSpent)
        external
        nonReentrant
        onlyKeeper
        whenNotPaused
    {
        address token = spdx;
        if (token == address(0)) revert TokenNotSet();
        if (amount == 0) revert BadAmount();

        uint256 spent = burnSpent[weekId] + usdgSpent;
        uint256 funded = burnFunded[weekId];
        if (spent > funded) revert BurnBudgetExceeded(spent, funded);
        burnSpent[weekId] = spent;

        uint256 free = _free(token);
        if (free < amount) revert InsufficientFreeBalance(free, amount);

        // §21/P1-1, burn hebdomadaire = TOUT OU RIEN, à la différence de la sortie de joueur : révoquer ANNULE
        // la destruction elle-même (rien n'est perdu, rien n'est mal publié), le keeper voit l'échec tout de
        // suite et rejoue ; les tokens non détruits restent dans le solde libre. Différer un reliquat ici
        // publierait `Burned(amount)` et un `usdgSpent` pour une destruction partielle, ce qui fausserait la
        // surveillance du prix payé (§5). La sortie, elle, ne peut pas révoquer : §8.1/§11.6 interdisent qu'un
        // joueur soit pris en otage par l'émetteur du token.
        if (_tryBurnSpdx(token, amount) != amount) revert BurnFailed();
        burnedTokens[weekId] += amount;
        emit Burned(weekId, amount, usdgSpent, IERC20Min(token).totalSupply());
    }

    // ================================================================== §6 Stock Draw

    /// @notice prouve qu'un round drand EXISTE, en vérifiant sa signature. **Ouverte à tous**, idempotente, ne
    ///         déplace rien : c'est une horloge, pas un pouvoir. Fait monter `maxPublishedRound` (monotone).
    function publishRound(uint64 round, bytes calldata sig96) external nonReentrant returns (bytes32) {
        return _publishRound(round, sig96);
    }

    /// @notice ouvre le tirage de la semaine : poids et dotation FIGÉS AVANT que le round drand soit connu.
    ///         **Réservée au Safe** (`onlyOwner`) depuis la v5 : voir §23/P0-1 (a) — `weightsRoot` est arbitraire,
    ///         donc ouvrir un tirage EST un pouvoir de sortie de fonds, qui n'a rien à faire sur une clé chaude.
    ///         La dotation doit DÉJÀ être détenue par le contrat (pas de tirage sans dotation).
    /// @dev    `weightsRoot` : feuilles keccak256(bytes.concat(keccak256(abi.encode(address player, uint256 weekId,
    ///         uint256 index, uint256 cumulativeFrom, uint256 cumulativeTo)))). Le PAVAGE EXACT de
    ///         [0, totalWeight) est garanti par construction côté indexeur (invariant §10.8) : une preuve
    ///         d'inclusion seule ne peut pas le vérifier. **Et le contrat ne vérifie PAS que les poids décrivent
    ///         les stakes réels** : voir la réserve portée par `setKeeper`.
    /// @param  proofRound / proofSig96 : un round drand RÉCENT et sa signature, exigés pour que le plancher
    ///         `maxPublishedRound + 2` ne soit pas inerte. Sans cette preuve, `maxPublishedRound` serait vieux
    ///         d'environ 201 600 rounds entre deux tirages hebdomadaires, et le plancher ne bornerait rien.
    function openDraw(
        uint256 weekId,
        bytes32 weightsRoot,
        uint256 totalWeight,
        address prizeToken,
        uint256 prizeAmount,
        uint64 proofRound,
        bytes calldata proofSig96
    ) external nonReentrant onlyOwner whenNotPaused {
        Draw storage d = _draws[weekId];
        if (d.weightsRoot != bytes32(0)) revert DrawAlreadyOpen();
        if (weightsRoot == bytes32(0)) revert BadRoot();
        if (totalWeight == 0 || totalWeight > type(uint128).max) revert BadAmount();
        if (prizeAmount == 0 || prizeAmount > type(uint128).max) revert BadAmount();
        if (prizeToken == address(0) || prizeToken.code.length == 0) revert BadConfig();

        uint256 free = _free(prizeToken);
        if (free < prizeAmount) revert InsufficientFreeBalance(free, prizeAmount);

        // §23/P0-2 — liaison au round drand, transplantée de `SpindexSpins._commit` (`:280-288`) AVEC sa défense.
        // `roundFor` garantit `publishTime(round) ≥ block.timestamp + DELTA`, ce qui ne protège QUE si le retard
        // de `block.timestamp` sur l'heure réelle reste sous DELTA. Au-delà, `roundFor` désigne un round DÉJÀ
        // publié par drand : `x = randomness mod totalWeight` devient calculable AVANT l'envoi, et il suffit
        // alors de choisir l'ORDRE des feuilles — poids tous sincères, pavage exact — pour gagner à coup sûr.
        // Défense : ne jamais lier au-dessous de `maxPublishedRound + 2`. Un round ≤ `maxPublishedRound` a déjà
        // son hasard prouvé ici ; `maxPublishedRound + 1` peut déjà être public chez drand. Le tirage est donc
        // lié au moins un round au-delà de ce que quiconque a pu prouver — par une horloge que le séquenceur ne
        // contrôle pas, et sans aucune hypothèse sur `block.timestamp`.
        _publishRound(proofRound, proofSig96);
        uint64 round = roundFor(block.timestamp);
        uint64 floorRound = maxPublishedRound + 2;
        if (round < floorRound) round = floorRound;
        // atteignable depuis la v5 : `round` peut venir du plancher, donc d'une ENTRÉE, et plus seulement de
        // l'horloge (avant la v5 il aurait fallu attendre l'an ~106 000). Gardé et testé.
        if (round > type(uint40).max) revert BadRound();

        prizeReserved[prizeToken] += prizeAmount;
        d.weightsRoot = weightsRoot;
        d.totalWeight = uint128(totalWeight);
        d.prizeToken = prizeToken;
        d.prizeAmount = uint128(prizeAmount);
        d.round = uint40(round);
        d.openedAt = uint64(block.timestamp);
        emit DrawOpened(weekId, weightsRoot, totalWeight, prizeToken, prizeAmount, round);
    }

    /// @notice règle le tirage avec la signature drand du round figé à l'ouverture. OUVERT À TOUS (personne ne peut
    ///         bloquer un règlement), pas bloqué par la pause : l'engagement est antérieur.
    /// @dev    Appel au vérificateur en `staticcall` PLAFONNÉ : une signature invalide fait brûler au précompilé
    ///         BLS tout le gaz transmis.
    function settleDraw(uint256 weekId, bytes calldata sig96) external nonReentrant {
        Draw storage d = _draws[weekId];
        if (d.weightsRoot == bytes32(0)) revert DrawNotOpen();
        if (d.randomness != bytes32(0)) revert DrawAlreadySettled();

        (bool ok, bytes memory ret) = address(verifier).staticcall{gas: VERIFY_GAS}(
            abi.encodeCall(DrandQuicknetVerifier.verifyUncompressed, (uint64(d.round), sig96))
        );
        if (!ok || ret.length != 32) revert InvalidBeacon();
        bytes32 rnd = abi.decode(ret, (bytes32));
        if (rnd == bytes32(0)) revert InvalidBeacon(); // 0 = « pas réglé » dans l'état : jamais accepté

        uint256 x = uint256(rnd) % uint256(d.totalWeight);
        d.randomness = rnd;
        d.winningX = uint128(x);
        d.settledAt = uint64(block.timestamp);
        // le règlement a vérifié une vraie signature drand : il alimente l'horloge, exactement comme chez
        // SpindexSpins (`:322`). Sans ça, `maxPublishedRound` n'avancerait que par `publishRound`.
        if (uint64(d.round) > maxPublishedRound) maxPublishedRound = uint64(d.round);
        emit DrawSettled(weekId, uint64(d.round), rnd, x);
    }

    /// @dev vérifie la signature drand de `round` en `staticcall` PLAFONNÉ (une signature invalide fait brûler
    ///      au précompilé BLS tout le gaz transmis) et fait monter l'horloge. Ne met rien en cache : le hasard
    ///      par round ne sert à rien ici (c'est `settleDraw` qui le calcule pour SA semaine), et un SSTORE par
    ///      round publié serait payé chaque semaine pour une donnée que personne ne relit.
    function _publishRound(uint64 round, bytes calldata sig96) private returns (bytes32 rnd) {
        (bool ok, bytes memory ret) = address(verifier).staticcall{gas: VERIFY_GAS}(
            abi.encodeCall(DrandQuicknetVerifier.verifyUncompressed, (round, sig96))
        );
        if (!ok || ret.length != 32) revert InvalidBeacon();
        rnd = abi.decode(ret, (bytes32));
        if (rnd == bytes32(0)) revert InvalidBeacon();
        if (round > maxPublishedRound) maxPublishedRound = round;
        emit RoundPublished(round, rnd);
    }

    /// @notice le gagnant se révèle par une preuve d'INTERVALLE : `cumulativeFrom ≤ x < cumulativeTo`.
    ///         Un seul gagnant possible pour un `x` donné (les intervalles pavent [0, totalWeight)), une seule fois.
    ///         Pas bloqué par la pause. La dotation part à `player`, pas à l'appelant.
    function claimPrize(
        uint256 weekId,
        address player,
        uint256 index,
        uint256 cumulativeFrom,
        uint256 cumulativeTo,
        bytes32[] calldata proof
    ) external nonReentrant {
        Draw storage d = _draws[weekId];
        if (d.weightsRoot == bytes32(0)) revert DrawNotOpen();
        if (d.randomness == bytes32(0)) revert DrawNotSettled();
        if (d.claimed) revert PrizeAlreadyClaimed();
        if (d.returned) revert PrizeAlreadyReturned();
        if (cumulativeFrom >= cumulativeTo || cumulativeTo > d.totalWeight) revert BadInterval();

        uint256 x = d.winningX;
        if (x < cumulativeFrom || x >= cumulativeTo) revert NotTheWinner(x);

        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(player, weekId, index, cumulativeFrom, cumulativeTo)))
        );
        if (!_verify(proof, d.weightsRoot, leaf)) revert BadProof();

        address prizeToken = d.prizeToken;
        uint256 amount = d.prizeAmount;
        d.claimed = true;
        prizeReserved[prizeToken] -= amount;
        uint256 sent = _sendMeasured(prizeToken, player, amount);
        emit PrizeClaimed(weekId, player, prizeToken, sent);
    }

    /// @notice sans réclamation 30 jours après le règlement (ou, si le tirage n'a jamais été réglé, 30 jours après
    ///         son ouverture), la dotation retourne au Safe.
    function returnPrize(uint256 weekId) external nonReentrant onlyOwner {
        Draw storage d = _draws[weekId];
        if (d.weightsRoot == bytes32(0)) revert DrawNotOpen();
        if (d.claimed) revert PrizeAlreadyClaimed();
        if (d.returned) revert PrizeAlreadyReturned();
        uint256 readyAt = uint256(d.settledAt != 0 ? d.settledAt : d.openedAt) + PRIZE_WINDOW;
        if (block.timestamp < readyAt) revert ReturnTooEarly(readyAt);

        address prizeToken = d.prizeToken;
        uint256 amount = d.prizeAmount;
        d.returned = true;
        prizeReserved[prizeToken] -= amount;
        emit PrizeReturned(weekId, prizeToken, amount);
        _send(prizeToken, owner, amount);
    }

    // ================================================================== §6 calcul des rounds (identique à SpinTickets)

    /// @notice heure de publication du round `round` (≥ 1).
    function publishTime(uint64 round) public view returns (uint64) {
        uint256 t = GENESIS + (uint256(round) - 1) * PERIOD; // round 0 : revert (sous-dépassement)
        if (t > type(uint64).max) revert BadRound();
        return uint64(t);
    }

    /// @notice premier round r (≥ 1) avec publishTime(r) ≥ ts + DELTA.
    function roundFor(uint256 ts) public view returns (uint64) {
        uint256 target = ts + DELTA;
        if (target <= GENESIS) return 1;
        return uint64((target - GENESIS + PERIOD - 1) / PERIOD + 1);
    }

    // ================================================================== §7 administration

    function setPaused(bool p) external onlyOwner {
        paused = p;
        emit PauseSet(p);
    }

    /// @notice keeper révocable (0 = personne). Depuis la v5, ses seuls pouvoirs sont `burn` (détruire des $SPDX
    ///         du solde LIBRE, dans la limite de l'enveloppe déclarée) et `postWeek`. `openDraw` lui a été
    ///         RETIRÉE (§23/P0-1).
    /// @dev    ⚠️ **Ce que le contrat garantit, et ce qu'il ne garantit pas.** Garanti : le keeper ne peut pas
    ///         transférer de jetons vers une adresse de son choix, ni toucher aux stakes, ni aux enveloppes
    ///         versées (`_free` les exclut), ni sortir un dollar du contrat.
    ///         **NON garanti : que les racines qu'il publie décrivent la réalité.** `postWeek` prend une
    ///         `merkleRoot` ARBITRAIRE : une racine dont une feuille le désigne lui-même le fait payer jusqu'à
    ///         `funded(weekId)` de la semaine. Le contrat ne vérifie aucune feuille contre un état on-chain — il
    ///         vérifie seulement une appartenance à une racine qu'on lui donne, et une borne d'enveloppe.
    ///         C'est un pouvoir de détournement borné par l'enveloppe, pas l'absence de pouvoir.
    ///         La borne réelle est **hors chaîne** : la table des feuilles doit être publiée et recoupée avant
    ///         chaque `postWeek` (§21/P1-2 corrigé). Tant que ce veilleur n'existe pas, cette garantie n'est
    ///         tenue par personne — et l'argument « pas de préavis de 48 h sur le keeper parce qu'il n'a aucun
    ///         pouvoir de sortie de fonds » est FAUX. Il a été retiré de la source et des rapports (§23/P0-1 b).
    function setKeeper(address newKeeper) external onlyOwner {
        keeper = newKeeper;
        emit KeeperSet(newKeeper);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ================================================================== lectures

    function stakeOf(address player) external view returns (uint256) {
        return _locks[player].amount;
    }

    function anchorOf(address player) external view returns (uint64) {
        return _locks[player].anchor;
    }

    /// @notice boost de fidélité courant, échelle 1e18 (×1 → ×3).
    function boostOf(address player) public view returns (uint256) {
        return _boost(_locks[player].anchor);
    }

    /// @notice stake EFFECTIF = montant × boost. C'est lui qui décide du rang et des poids du tirage.
    function effectiveStakeOf(address player) public view returns (uint256) {
        Lock memory l = _locks[player];
        if (l.amount == 0) return 0;
        return uint256(l.amount) * _boost(l.anchor) / BOOST_ONE;
    }

    function rankOf(address player) public view returns (Rank) {
        uint256 e = effectiveStakeOf(player);
        if (e >= RANK_MEGA) return Rank.Mega;
        if (e >= RANK_LARGE) return Rank.Large;
        if (e >= RANK_MID) return Rank.Mid;
        if (e >= RANK_SMALL) return Rank.Small;
        return Rank.Penny;
    }

    /// @notice taux de rakeback du rang, en bps. Le contrat ne s'en sert PAS (calcul hors chaîne) : il l'expose
    ///         pour que l'interface et l'indexeur lisent la même source (§2).
    function rakebackBpsOf(address player) external view returns (uint256) {
        Rank r = rankOf(player);
        if (r == Rank.Mega) return 3_000;
        if (r == Rank.Large) return 2_000;
        if (r == Rank.Mid) return 1_000;
        if (r == Rank.Small) return 500;
        return 0;
    }

    function getWeek(uint256 weekId)
        external
        view
        returns (
            bytes32 root,
            uint256 funded,
            uint256 claimed_,
            uint64 fundedAt,
            uint64 postedAt,
            uint32 leafCount,
            bool swept
        )
    {
        Week memory w = _weeks[weekId];
        return (w.root, w.funded, w.claimed, w.fundedAt, w.postedAt, w.leafCount, w.swept);
    }

    function getDraw(uint256 weekId) external view returns (Draw memory) {
        return _draws[weekId];
    }

    /// @notice solde LIBRE d'un token : ce que le contrat détient au-delà de ses passifs (stakes, burns différés,
    ///         enveloppes de semaine non payées, dotations engagées). Assiette du burn et des dotations.
    function freeBalance(address token) external view returns (uint256) {
        return _free(token);
    }

    // ================================================================== interne : merkle (reconnaissance §5)

    /// @dev paires triées, aucune dépendance externe. La feuille est DOUBLE hachée par l'appelant : le domaine des
    ///      feuilles est séparé de celui des nœuds internes, donc une preuve de 64 octets ne peut pas être
    ///      réinterprétée comme une feuille valide (seconde préimage).
    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) private pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i; i < proof.length; ++i) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(bytes.concat(h, p)) : keccak256(bytes.concat(p, h));
        }
        return h == root;
    }

    // ================================================================== interne : boost

    function _boost(uint64 anchor) private view returns (uint256) {
        if (anchor == 0 || block.timestamp <= anchor) return BOOST_ONE;
        uint256 e = block.timestamp - anchor;
        if (e > BOOST_CAP_ELAPSED) e = BOOST_CAP_ELAPSED;
        return BOOST_ONE + BOOST_ONE * e / BOOST_RAMP;
    }

    /// @dev Récolte du rakeback : c'est le MULTIPLICATEUR qui est divisé par deux, jamais sous ×1 (spec §15) —
    ///      ×3 → ×1,5, et NON ×3 → ×2. Diviser l'ancienneté (lecture antérieure) donnerait ×2 : les deux lectures
    ///      ne coïncident qu'à ×1, donc le choix est visible dès la première récolte d'un joueur à ×3.
    ///      L'ancre est ensuite RECALCULÉE pour correspondre au nouveau multiplicateur : le boost étant affine en
    ///      l'ancienneté plafonnée (b = 1 + e/30 j), `e' = (b' − 1) × 30 j`.
    ///      Le plancher `nb < BOOST_ONE` est load-bearing : sans lui, une seconde récolte (b = 1,5 ⇒ b/2 = 0,75)
    ///      ferait déborder `nb − BOOST_ONE` par le bas. Le boost ne remonte jamais (`newAnchor ≥ l.anchor`).
    function _halveBoost(address player) private {
        Lock memory l = _locks[player];
        if (l.amount == 0 || l.anchor == 0) return;
        uint256 nb = _boost(l.anchor) / 2;
        if (nb < BOOST_ONE) nb = BOOST_ONE;
        uint256 e = (nb - BOOST_ONE) * BOOST_RAMP / BOOST_ONE;
        uint64 newAnchor = uint64(block.timestamp - e);
        if (newAnchor <= l.anchor) return; // déjà à ×1 : rien à faire, et jamais de remontée
        _locks[player].anchor = newAnchor;
        emit BoostHalved(player, l.anchor, newAnchor);
    }

    // ================================================================== interne : comptabilité

    /// @dev passif du contrat pour `token`. Tout le reste est LIBRE.
    function _reserved(address token) private view returns (uint256 r) {
        r = prizeReserved[token];
        if (token == spdx) r += totalStaked + strandedBurn;
        else if (token == usdg) r += usdgReserved;
    }

    function _free(address token) private view returns (uint256) {
        uint256 bal = IERC20Min(token).balanceOf(address(this));
        uint256 res = _reserved(token);
        return bal > res ? bal - res : 0;
    }

    // ================================================================== interne : $SPDX burn

    /// @dev appelle `burn(uint256)` du token et renvoie le montant RÉELLEMENT DÉTRUIT, mesuré sur l'offre :
    ///      `s0 − s1` (invariant §8.5 : c'est l'offre qui prouve, jamais le retour de l'appel). Renvoie **0**
    ///      si l'appel révoque, si l'offre ne bouge pas, ou si elle MONTE.
    ///      Le retour peut être INFÉRIEUR à `amount` (destruction partielle) ou SUPÉRIEUR (sur-destruction) :
    ///      l'aide ne révèle pas, l'appelant décide — sous la règle §21/P1-1 « aucun chemin n'inscrit un passif
    ///      supérieur à ce qui a été réellement détruit, aucun chemin ne compte deux fois ».
    ///      `BurnMismatch` signale l'anomalie NOUVELLE (partielle / excédentaire) et seulement elle : « rien
    ///      détruit » est déjà porté par `ExitBurnDeferred` côté sortie et par `BurnFailed` côté keeper, et
    ///      l'émettre ici changerait les journaux des modes déjà couverts par les vecteurs dorés.
    function _tryBurnSpdx(address token, uint256 amount) private returns (uint256 burned) {
        uint256 s0 = IERC20Min(token).totalSupply();
        (bool ok,) = token.call{gas: BURN_GAS}(abi.encodeWithSelector(SEL_BURN, amount));
        if (!ok) return 0;
        uint256 s1 = IERC20Min(token).totalSupply();
        if (s1 >= s0) return 0;
        burned = s0 - s1;
        if (burned != amount) emit BurnMismatch(amount, burned);
    }

    // ================================================================== interne : SafeERC20 minimal

    /// @dev `transfer` : succès exigé (retour vide sur un token sans bool, ou mot = 1) ; renvoie le montant
    ///      RÉELLEMENT REÇU PAR `to` (delta de son solde) — c'est lui qui est journalisé, jamais `amount`.
    ///      Côté bénéficiaire et non côté contrat : le token d'agent Virtuals débite l'émetteur de `amount` et
    ///      ne crédite que `amount − frais` au destinataire (reconnaissance §1.3, contrôle positif à 100 bps).
    ///      C'est donc la seule mesure qui dit la vérité au joueur.
    function _sendMeasured(address token, address to, uint256 amount) private returns (uint256 sent) {
        uint256 before = IERC20Min(token).balanceOf(to);
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, shl(224, 0xa9059cbb)) // transfer(address,uint256)
            mstore(add(m, 0x04), to)
            mstore(add(m, 0x24), amount)
            mstore(0x00, 0)
            ok := call(gas(), token, 0, m, 0x44, 0x00, 0x20)
            if ok {
                switch returndatasize()
                case 0 { ok := gt(extcodesize(token), 0) }
                default { ok := and(iszero(lt(returndatasize(), 0x20)), eq(mload(0x00), 1)) }
            }
        }
        if (!ok) revert TransferFailed();
        uint256 after_ = IERC20Min(token).balanceOf(to);
        return after_ > before ? after_ - before : 0;
    }

    function _send(address token, address to, uint256 amount) private {
        _sendMeasured(token, to, amount);
    }

    /// @dev `transferFrom(from, this, amount)` ; renvoie le montant RÉELLEMENT reçu (delta de solde). L'appelant
    ///      décide quoi en faire (`stake` refuse tout écart, cf. §2).
    function _pullMeasured(address token, address from, uint256 amount) private returns (uint256 received) {
        uint256 before = IERC20Min(token).balanceOf(address(this));
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, shl(224, 0x23b872dd)) // transferFrom(address,address,uint256)
            mstore(add(m, 0x04), from)
            mstore(add(m, 0x24), address())
            mstore(add(m, 0x44), amount)
            mstore(0x00, 0)
            ok := call(gas(), token, 0, m, 0x64, 0x00, 0x20)
            if ok {
                switch returndatasize()
                case 0 { ok := gt(extcodesize(token), 0) }
                default { ok := and(iszero(lt(returndatasize(), 0x20)), eq(mload(0x00), 1)) }
            }
        }
        if (!ok) revert TransferFailed();
        uint256 after_ = IERC20Min(token).balanceOf(address(this));
        return after_ > before ? after_ - before : 0;
    }
}
