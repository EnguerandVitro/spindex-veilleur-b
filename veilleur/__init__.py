"""SPINDEX — le veilleur.

Composant de SÉCURITÉ en lecture seule. Il ne détient aucune clé de chaîne et ne signe aucune
transaction : sa seule clé est une clé d'attestation Ed25519, structurellement incapable de produire
une signature EVM.

Ce qu'il tient : la garantie de `REWARDS_SPEC.md` §21, qu'aucun code de contrat ne porte. `postWeek`
et `openDraw` acceptent une racine merkle ARBITRAIRE ; la borne réelle est hors chaîne. Sans ce
composant, le pouvoir du Safe sur les dotations et les enveloppes n'est borné par personne.
"""
__all__ = ["config", "rpc", "chainabi", "merkle", "tables", "reconstruct", "chainread",
           "controls", "ledger", "longfuse", "verdict", "attest", "service"]
