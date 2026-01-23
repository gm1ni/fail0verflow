#!/usr/bin/env python3
"""

TP Cryptanalyse - fail0verflow
Attaque ECDSA sur PS3

Auteur : Lucas FERRAND
Classe : GCS4
Date : 01/2026

"""

# Importation des bibliothèques
import json
import hashlib
import secrets
from ec_utils import P, A, B, N, G, Point
from ec_utils import point_add, point_multiply, mod_inverse

print("=" * 70)
print ("Attaque ECDSA sur PS3 - TP fail0verflow")
print("=" * 70)
print()

# Phase 1 : Implémentation de l'attaque ECDSA
def generate_keypair():
    """
    Génère une paire de clés ECDSA

    Returns: 
        (d, Q) : clé privée (int), clé publique (Point)
    """

    print("[Phase 1.1] Génération de clés...")

    
    # Phase 1.1 : Génération de clés
    """
    Etape 1 : Génération de la clé privée d
    
    Utilisation de secrets.randbelow(N - 1) + 1 pour obtenir un entier dans [1, N-1]
    NB : secrets.randbelow(N - 1) génère un entier aléatoire dans [0, N-2], donc on ajoute 1

    Problème : secrets.randbelow(N - 1) + 1 génère une clé valide, mais dont la taille en bits peut varier 
    (ex : 159 bits au lieu de 160 bits).

    Solution : Générer un entier aléatoire sur 160 bits, puis forcer le bit de poids fort à 1 pour garantir bit_length = 160.
    Rejeter ensuite la valeur si elle n'est pas dans l'intervalle [1, N-1].
    """

    while True:
        #  Génère un entier aléatoire sur 160 bits
        d = secrets.randbits(160)

        # Forcer le bit de poids fort à 1 pour garantir une taille de 160 bits
        d |= (1 << 159)

        # Vérifier que la clé privée d est valide pour ECDSA
        if 1 <= d < N:
            break

    # Etape 2 : Calcul de la clé publique Q = d * G
    # Utilisation de point_multiply(d, G) pour le calcul
    # NB : G est le point générateur de la courbe elliptique (déjà défini dans ec_utils.py)

    Q = point_multiply(d, G)

    print(f"  -> Clé privée générée (taille : {d.bit_length()} bits)")
    print(f"  -> Clé publique calculée")

    return d, Q


# Test phase 1
if __name__ == "__main__":
    print("\n" + "-" *  70)
    print("Test phase 1.1 : Génration de clés")
    print("-" *  70 + "\n")

    # Test de la fonction generate_keypair
    d, Q = generate_keypair()
    print(f"✓ Clé privée d = {hex(d)[:20]}...")
    print(f"✓ Clé publique Q = {Q}")
    
    # Vérification que Q est sur la courbe
    if Q.is_on_curve():
        print("✓ La clé publique Q est sur la courbe.")
    else:
        print("✗ Erreur : La clé publique Q n'est pas sur la courbe.")

    print("Phase 1 terminée.")


# Phase 2 : Récupération de la clé privée à partir de deux signatures ECDSA avec le même nonce
def recover_private_key(r, s1, s2, z1, z2):
    """
    Récupère la clé privéed à partir de deux signatures ECDSA utilisant le même nonce k 
    
    Args:
        r (int): composante r des signatures
        s1 (int): composante s de la première signature
        s2 (int): composante s de la deuxième signature
        z1 (int): hash du premier message signé
        z2 (int): hash du deuxième message signé

    Returns:
        d (int): clé privée récupérée
    """

    print("[Phase 2.1] Récupération de la clé privée à partir de deux signatures ECDSA avec le même nonce...")
    
    # Étape 1 : Calcul du nonce k
    s_diff = (s1 - s2) % N
    z_diff = (z1 - z2) % N
    s_diff_inv = mod_inverse(s_diff, N)
    k = (z_diff * s_diff_inv) % N
    print("  -> Nonce k calculé")

    # Étape 2 : Calcul de la clé privée d
    r_inv = mod_inverse(r, N)
    d = ((s1 * k - z1) * r_inv) % N
    print("  -> Clé privée d récupérée")
    return d

# Test phase 2
if __name__ == "__main__":
    print("\n" + "-" *  70)
    print("Test phase 2.1 : Récupération de la clé privée à partir de deux signatures ECDSA avec le même nonce")
    print("-" *  70 + "\n")

    # Exemple de données de test
    r_test = 0x1A2B3C4D5E6F
    s1_test = 0x1234567890AB
    s2_test = 0x0FEDCBA98765
    z1_test = 0xABCDEF123456
    z2_test = 0x654321FEDCBA

    # Récupération de la clé privée
    d_recovered = recover_private_key(r_test, s1_test, s2_test, z1_test, z2_test)
    print(f"✓ Clé privée récupérée d = {hex(d_recovered)[:20]}...")

    print("Phase 2 terminée.")


# Phase 3 : Vérification de la clé privée récupérée

