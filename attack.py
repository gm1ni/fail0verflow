#!/usr/bin/env python3
"""
TP Cryptanalyse – Operation fail0verflow
Attaque par réutilisation de nonce sur ECDSA (PlayStation 3)

Objectif :
- Comprendre le fonctionnement d’ECDSA
- Détecter une réutilisation de nonce k
- Exploiter cette vulnérabilité pour retrouver la clé privée
- Forger une signature valide (homebrew)

Courbe utilisée : VSH (160 bits) – PlayStation 3

Auteur : Lucas FERRAND
Classe : GCS4
Date : 01/2026
"""

import json
import hashlib
import secrets

# Import des primitives de la courbe elliptique
from ec_utils import (
    P, A, B, N, G,          # Paramètres de la courbe VSH
    Point,                  # Représentation d’un point elliptique
    point_add,              # Addition de points
    point_multiply,         # Multiplication scalaire
    mod_inverse             # Inverse modulaire
)

# ==========================================================
# OUTILS
# ==========================================================
def load_data(filename: str) -> dict:
    """
    Charge les données JSON fournies par l'enseignant.
    Contient :
        - la clé publique Sony
        - les firmwares signés vulnérables
    """
    with open(filename, "r") as f:
        return json.load(f)

# ==========================================================
# PHASE 1 – Comprendre ECDSA
# ==========================================================
def generate_keypair():
    """
    Génère une paire de clés ECDSA.

    Clé privée :
        d ∈ [1, N-1]

    Clé publique :
        Q = d · G

    Returns:
        d (int)  : clé privée
        Q (Point): clé publique
    """
    d = secrets.randbelow(N - 1) + 1
    Q = point_multiply(d, G)
    return d, Q


def sign_message(message: bytes, private_key: int, k: int = None):
    """
    Signe un message avec ECDSA.

    Étapes :
    1. e = SHA1(message)
    2. Choix du nonce k
    3. R = k · G
    4. r = R.x mod N
    5. s = k⁻¹(e + d·r) mod N

    IMPORTANT :
    - Si k est réutilisé, la clé privée peut être retrouvée.

    Returns:
        (r, s, k)
    """
    e = int(hashlib.sha1(message).hexdigest(), 16)

    if k is None:
        k = secrets.randbelow(N - 1) + 1

    # Calcul du point R
    R = point_multiply(k, G)

    r = R.x % N
    if r == 0:
        raise ValueError("Nonce invalide (r = 0)")

    k_inv = mod_inverse(k, N)
    s = (k_inv * (e + private_key * r)) % N
    if s == 0:
        raise ValueError("Nonce invalide (s = 0)")

    return r, s, k


def verify_signature(message: bytes, signature: tuple, public_key: Point):
    """
    Vérifie une signature ECDSA.

    Formule :
        R' = (e·s⁻¹)G + (r·s⁻¹)Q
        Signature valide si R'.x ≡ r (mod N)

    Returns:
        True si valide, False sinon
    """
    r, s = signature

    if not (1 <= r < N and 1 <= s < N):
        return False

    e = int(hashlib.sha1(message).hexdigest(), 16)

    s_inv = mod_inverse(s, N)
    u1 = (e * s_inv) % N
    u2 = (r * s_inv) % N

    R_prime = point_add(
        point_multiply(u1, G),
        point_multiply(u2, public_key)
    )

    if R_prime.is_infinity():
        return False

    return (R_prime.x % N) == (r % N)

# ==========================================================
# PHASE 2 – Détection de la vulnérabilité
# ==========================================================
def detect_nonce_reuse(firmwares: list) -> list:
    """
    Détecte les firmwares signés avec un nonce identique.

    Principe :
        - r = (k·G).x mod N
        - Même r  ⇒ même k

    Returns:
        Liste de paires (fw1, fw2) vulnérables
    """
    by_r = {}

    for fw in firmwares:
        r = int(fw["signature"]["r"], 16)
        by_r.setdefault(r, []).append(fw)

    pairs = []
    for r, fw_list in by_r.items():
        if len(fw_list) >= 2:
            for i in range(len(fw_list)):
                for j in range(i + 1, len(fw_list)):
                    pairs.append((fw_list[i], fw_list[j]))

    return pairs

# ==========================================================
# PHASE 3 – Attaque fail0verflow
# ==========================================================
def recover_nonce(e1: int, s1: int, e2: int, s2: int) -> int:
    """
    Récupère le nonce k à partir de deux signatures utilisant le même k.

    Formule :
        k = (e1 − e2) · (s1 − s2)⁻¹ mod N
    """
    num = (e1 - e2) % N
    den = (s1 - s2) % N
    return (num * mod_inverse(den, N)) % N


def recover_private_key(e: int, r: int, s: int, k: int) -> int:
    """
    Récupère la clé privée d :

        d = r⁻¹ · (k·s − e) mod N
    """
    return (mod_inverse(r, N) * (k * s - e)) % N


def full_attack(fw1: dict, fw2: dict) -> int:
    """
    Exécute l’attaque complète :
        1. Extraction des paramètres
        2. Récupération du nonce
        3. Calcul de la clé privée
    """
    e1 = int(fw1["hash"], 16)
    r  = int(fw1["signature"]["r"], 16)
    s1 = int(fw1["signature"]["s"], 16)

    e2 = int(fw2["hash"], 16)
    s2 = int(fw2["signature"]["s"], 16)

    k = recover_nonce(e1, s1, e2, s2)
    d = recover_private_key(e1, r, s1, k)

    return d

# ==========================================================
# PHASE 4 – Forge d’un homebrew signé
# ==========================================================
def create_signed_homebrew(private_key: int, data: bytes) -> dict:
    """
    Forge un homebrew signé avec la clé privée Sony récupérée.

    IMPORTANT :
        Cette fois-ci, le nonce est bien aléatoire.
    """
    r, s, _ = sign_message(data, private_key)

    return {
        "data": data.decode(),
        "signature": {
            "r": hex(r),
            "s": hex(s)
        }
    }

def verify_homebrew(public_key: Point, homebrew: dict) -> bool:
    """Vérifie la signature du homebrew forgé."""
    data = homebrew["data"].encode()
    r = int(homebrew["signature"]["r"], 16)
    s = int(homebrew["signature"]["s"], 16)
    return verify_signature(data, (r, s), public_key)

# ==========================================================
# PHASE 5 - FICHIER DE DONNEES GENERE
# ==========================================================
def save_json(filename: str, obj: dict) -> None:
    """Sauvegarde un dictionnaire au format JSON (livrable TP)."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    print("=== Operation fail0verflow ===\n")

    data = load_data("firmwares.json")

    pub_x = int(data["public_key"]["x"], 16)
    pub_y = int(data["public_key"]["y"], 16)
    public_key = Point(pub_x, pub_y)

    # ----------------------------
    # Phase 2 : Détection
    # ----------------------------
    print("[*] Phase 2 : Détection des nonces réutilisés")
    pairs = detect_nonce_reuse(data["firmwares"])

    if not pairs:
        raise RuntimeError("Aucune réutilisation de nonce détectée dans firmwares.json")

    print(f"[+] Paires détectées : {len(pairs)}")
    fw1, fw2 = pairs[0]
    print(f"[+] Exemple paire : {fw1['version']} <-> {fw2['version']}")
    print(f"[+] r commun : {fw1['signature']['r']}")

    # ----------------------------
    # Phase 3 : Attaque (clé privée)
    # ----------------------------
    print("\n[*] Phase 3 : Récupération de la clé privée")
    private_key = full_attack(fw1, fw2)
    print(f"[+] Clé privée Sony récupérée : {hex(private_key)}")

    # Vérification demandée par le TP : Q' = d·G == Q ?
    Q_check = point_multiply(private_key, G)
    if Q_check.x == public_key.x and Q_check.y == public_key.y:
        print("[+] Vérification Q' = d·G : OK")
    else:
        print("[!] Vérification Q' = d·G : KO (à investiguer)")

    # ----------------------------
    # Phase 4 : Forge (homebrew)
    # ----------------------------
    print("\n[*] Phase 4 : Forge du homebrew")
    msg = b"fail0verflow says: Hello World!"
    homebrew = create_signed_homebrew(private_key, msg)

    print("[+] Signature valide ?",
          verify_homebrew(public_key, homebrew))

    # ----------------------------
    # Livrable : fichier généré
    # ----------------------------
    save_json("homebrew_signed.json", homebrew)
    print("[+] Fichier généré : homebrew_signed.json")

    print("\n[+] Attaque terminée avec succès")
