"""Le compteur de passe tel qu'il est AVANT l'exécution — la base de la jambe de progression.

Lu depuis l'état restauré (la branche), jamais depuis l'exécution en cours : c'est ce qui permet au
jugement d'exiger une progression POSITIVE plutôt que de se contenter de « un fichier existe »
(KE#131). Imprime le nombre, ou « aucun » si rien n'a été restauré — et « aucun » n'est pas 0 :
une première exécution et une exécution qui n'a rien écrit ne se confondent pas.
"""
import json
import sys


def main(argv):
    if len(argv) < 2:
        print("aucun")
        return 0
    try:
        with open(argv[1], encoding="utf-8") as fh:
            print(int(json.load(fh).get("passe") or 0))
    except (OSError, ValueError, TypeError):
        print("aucun")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
