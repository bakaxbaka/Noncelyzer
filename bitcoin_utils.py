#!/usr/bin/env python3
"""
Bitcoin Utilities for Address Generation, Balance Checking, and Verification
Integrated with ECDSA calculator logic for comprehensive Bitcoin analysis
"""

import hashlib
import base58
import requests
import time
from typing import Dict, List, Tuple, Optional, Any
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.numbertheory import inverse_mod
from ecdsa.ellipticcurve import Point

# Bitcoin constants
SECP256K1_N = SECP256k1.order
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

class BitcoinUtils:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bitcoin-Utils/1.0'
        })
        self.blockstream_api = "https://blockstream.info/api"
        self.ethereum_api = "https://api.etherscan.io/api"
        
    def private_key_to_wif(self, private_key: int, compressed: bool = True, testnet: bool = False) -> str:
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
    
    def wif_to_private_key(self, wif: str) -> Tuple[int, bool, bool]:
        """Convert WIF to private key, returns (private_key, compressed, testnet)"""
        try:
            decoded = base58.b58decode(wif)
            
            # Verify checksum
            checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
            if checksum != decoded[-4:]:
                raise ValueError("Invalid WIF checksum")
            
            # Determine network and compression
            if decoded[0] == 0x80:  # Mainnet
                testnet = False
            elif decoded[0] == 0xef:  # Testnet
                testnet = True
            else:
                raise ValueError("Invalid WIF version byte")
            
            # Check compression flag
            if len(decoded) == 37:  # Uncompressed
                compressed = False
                private_key_bytes = decoded[1:-4]
            elif len(decoded) == 38 and decoded[-5] == 0x01:  # Compressed
                compressed = True
                private_key_bytes = decoded[1:-5]
            else:
                raise ValueError("Invalid WIF length")
            
            private_key = int.from_bytes(private_key_bytes, byteorder='big')
            return private_key, compressed, testnet
            
        except Exception as e:
            raise ValueError(f"Failed to decode WIF: {e}")
    
    def private_key_to_public_key(self, private_key: int) -> Tuple[int, int]:
        """Convert private key to public key coordinates (x, y)"""
        try:
            # Create signing key from private key
            sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
            vk = sk.verifying_key
            
            # Get public key point
            public_key_point = vk.pubkey.point
            return public_key_point.x(), public_key_point.y()
            
        except Exception as e:
            raise ValueError(f"Failed to convert to public key: {e}")
    
    def public_key_to_address(self, x: int, y: int, compressed: bool = True, testnet: bool = False) -> str:
        """Convert public key coordinates to Bitcoin address"""
        try:
            if compressed:
                # Compressed public key format
                if y % 2 == 0:
                    public_key_bytes = b'\x02' + x.to_bytes(32, 'big')
                else:
                    public_key_bytes = b'\x03' + x.to_bytes(32, 'big')
            else:
                # Uncompressed public key format
                public_key_bytes = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
            
            # Create Bitcoin address (P2PKH)
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
            raise ValueError(f"Failed to convert to address: {e}")
    
    def private_key_to_address(self, private_key: int, compressed: bool = True, testnet: bool = False) -> str:
        """Convert private key directly to Bitcoin address"""
        x, y = self.private_key_to_public_key(private_key)
        return self.public_key_to_address(x, y, compressed, testnet)
    
    def get_address_balance(self, address: str) -> Dict:
        """Get Bitcoin address balance and transaction info"""
        try:
            # Get address stats
            response = self.session.get(f"{self.blockstream_api}/address/{address}", timeout=30)
            response.raise_for_status()
            
            address_data = response.json()
            
            # Convert satoshis to BTC
            balance_satoshis = address_data.get('chain_stats', {}).get('funded_txo_sum', 0) - \
                              address_data.get('chain_stats', {}).get('spent_txo_sum', 0)
            balance_btc = balance_satoshis / 100000000
            
            return {
                'address': address,
                'balance_satoshis': balance_satoshis,
                'balance_btc': balance_btc,
                'tx_count': address_data.get('chain_stats', {}).get('tx_count', 0),
                'total_received': address_data.get('chain_stats', {}).get('funded_txo_sum', 0),
                'total_sent': address_data.get('chain_stats', {}).get('spent_txo_sum', 0),
                'unconfirmed_balance': address_data.get('mempool_stats', {}).get('funded_txo_sum', 0) - \
                                     address_data.get('mempool_stats', {}).get('spent_txo_sum', 0)
            }
            
        except Exception as e:
            raise ValueError(f"Failed to get balance for {address}: {e}")
    
    def get_address_transactions(self, address: str, limit: int = 25) -> List[Dict]:
        """Get recent transactions for an address"""
        try:
            response = self.session.get(f"{self.blockstream_api}/address/{address}/txs", timeout=30)
            response.raise_for_status()
            
            transactions = response.json()[:limit]
            
            # Process transactions to add value calculations
            processed_txs = []
            for tx in transactions:
                tx_info = {
                    'txid': tx['txid'],
                    'confirmations': tx.get('status', {}).get('block_height', 0),
                    'time': tx.get('status', {}).get('block_time', 0),
                    'fee': tx.get('fee', 0),
                    'size': tx.get('size', 0),
                    'value_in': 0,
                    'value_out': 0
                }
                
                # Calculate values for this address
                for vin in tx.get('vin', []):
                    if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                        tx_info['value_in'] += vin.get('prevout', {}).get('value', 0)
                
                for vout in tx.get('vout', []):
                    if vout.get('scriptpubkey_address') == address:
                        tx_info['value_out'] += vout.get('value', 0)
                
                processed_txs.append(tx_info)
            
            return processed_txs
            
        except Exception as e:
            raise ValueError(f"Failed to get transactions for {address}: {e}")
    
    def verify_private_key_address_pair(self, private_key: int, address: str) -> Dict:
        """Verify that a private key corresponds to a given address"""
        try:
            # Try both compressed and uncompressed formats
            results = []
            
            for compressed in [True, False]:
                for testnet in [False, True]:
                    try:
                        generated_address = self.private_key_to_address(private_key, compressed, testnet)
                        if generated_address == address:
                            results.append({
                                'match': True,
                                'compressed': compressed,
                                'testnet': testnet,
                                'generated_address': generated_address
                            })
                    except Exception:
                        continue
            
            if results:
                return {
                    'verified': True,
                    'matches': results,
                    'private_key_hex': hex(private_key),
                    'private_key_wif': self.private_key_to_wif(private_key, results[0]['compressed'], results[0]['testnet'])
                }
            else:
                return {
                    'verified': False,
                    'matches': [],
                    'error': 'Private key does not correspond to the given address'
                }
                
        except Exception as e:
            return {
                'verified': False,
                'error': f"Verification failed: {e}"
            }
    
    def validate_point_on_curve(self, x: int, y: int) -> bool:
        """Validate that a point (x, y) is on the secp256k1 curve: y² = x³ + 7 mod p"""
        try:
            # Calculate y² mod p
            y_squared = (y * y) % SECP256K1_P
            
            # Calculate x³ + 7 mod p
            x_cubed_plus_7 = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
            
            return y_squared == x_cubed_plus_7
            
        except Exception:
            return False
    
    def comprehensive_key_analysis(self, private_key: int) -> Dict:
        """Perform comprehensive analysis of a private key"""
        try:
            # Get public key coordinates
            pub_x, pub_y = self.private_key_to_public_key(private_key)
            
            # Validate public key point
            point_valid = self.validate_point_on_curve(pub_x, pub_y)
            
            # Generate all possible addresses
            addresses = {}
            wif_keys = {}
            
            for compressed in [True, False]:
                for testnet in [False, True]:
                    try:
                        address = self.public_key_to_address(pub_x, pub_y, compressed, testnet)
                        wif = self.private_key_to_wif(private_key, compressed, testnet)
                        
                        key = f"{'compressed' if compressed else 'uncompressed'}_{'testnet' if testnet else 'mainnet'}"
                        addresses[key] = address
                        wif_keys[key] = wif
                        
                    except Exception as e:
                        key = f"{'compressed' if compressed else 'uncompressed'}_{'testnet' if testnet else 'mainnet'}"
                        addresses[key] = f"Error: {e}"
                        wif_keys[key] = f"Error: {e}"
            
            # Get balance information for mainnet addresses
            balances = {}
            for key, address in addresses.items():
                if 'mainnet' in key and not address.startswith('Error:'):
                    try:
                        balance_info = self.get_address_balance(address)
                        balances[key] = balance_info
                    except Exception as e:
                        balances[key] = {'error': str(e)}
            
            return {
                'private_key_hex': hex(private_key),
                'private_key_decimal': str(private_key),
                'public_key': {
                    'x': hex(pub_x),
                    'y': hex(pub_y),
                    'x_decimal': str(pub_x),
                    'y_decimal': str(pub_y),
                    'valid_point': point_valid
                },
                'addresses': addresses,
                'wif_keys': wif_keys,
                'balances': balances,
                'key_range_check': {
                    'valid_range': 0 < private_key < SECP256K1_N,
                    'min_value': 1,
                    'max_value': SECP256K1_N - 1,
                    'current_value': private_key
                }
            }
            
        except Exception as e:
            return {'error': f"Analysis failed: {e}"}
    
    def batch_address_generation(self, start_key: int, count: int = 100) -> List[Dict]:
        """Generate multiple addresses from sequential private keys"""
        results = []
        
        for i in range(count):
            private_key = start_key + i
            
            if private_key >= SECP256K1_N:
                break
            
            try:
                analysis = self.comprehensive_key_analysis(private_key)
                results.append(analysis)
                
            except Exception as e:
                results.append({
                    'private_key_hex': hex(private_key),
                    'error': str(e)
                })
        
        return results
    
    def find_address_with_balance(self, start_key: int, max_iterations: int = 1000) -> Optional[Dict]:
        """Search for an address with balance starting from a given private key"""
        for i in range(max_iterations):
            private_key = start_key + i
            
            if private_key >= SECP256K1_N:
                break
            
            try:
                # Generate mainnet compressed address (most common)
                address = self.private_key_to_address(private_key, compressed=True, testnet=False)
                balance_info = self.get_address_balance(address)
                
                if balance_info['balance_satoshis'] > 0:
                    # Found an address with balance
                    analysis = self.comprehensive_key_analysis(private_key)
                    analysis['found_at_iteration'] = i
                    return analysis
                
                # Rate limiting
                if i % 10 == 0:
                    time.sleep(0.1)
                    
            except Exception as e:
                print(f"Error checking key {hex(private_key)}: {e}")
                continue
        
        return None
    
    def private_key_to_ethereum_address(self, private_key: int) -> str:
        """Convert private key to Ethereum address"""
        try:
            # Create signing key from private key
            sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
            vk = sk.verifying_key
            
            # Get public key point
            public_key_point = vk.pubkey.point
            x = public_key_point.x()
            y = public_key_point.y()
            
            # Ethereum uses uncompressed public key format without 0x04 prefix
            public_key_bytes = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
            
            # Keccak-256 hash of public key
            keccak_hash = hashlib.sha3_256(public_key_bytes).digest()
            
            # Take last 20 bytes and add 0x prefix
            eth_address = '0x' + keccak_hash[-20:].hex()
            
            return eth_address
            
        except Exception as e:
            raise ValueError(f"Failed to convert to Ethereum address: {e}")
    
    def get_ethereum_balance(self, address: str) -> Dict:
        """Get Ethereum address balance"""
        try:
            # Get ETH balance
            balance_url = f"{self.ethereum_api}?module=account&action=balance&address={address}&tag=latest"
            response = self.session.get(balance_url, timeout=30)
            response.raise_for_status()
            
            balance_data = response.json()
            if balance_data.get('status') != '1':
                return {'error': f"API error: {balance_data.get('message', 'Unknown error')}"}
            
            # Convert Wei to ETH
            balance_wei = int(balance_data['result'])
            balance_eth = balance_wei / 10**18
            
            # Get transaction count
            txcount_url = f"{self.ethereum_api}?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest"
            tx_response = self.session.get(txcount_url, timeout=30)
            tx_response.raise_for_status()
            
            tx_data = tx_response.json()
            tx_count = int(tx_data.get('result', '0x0'), 16) if tx_data.get('result') else 0
            
            return {
                'address': address,
                'balance_wei': balance_wei,
                'balance_eth': balance_eth,
                'tx_count': tx_count,
                'network': 'ethereum'
            }
            
        except Exception as e:
            return {'error': f"Failed to get Ethereum balance: {e}"}
    
    def get_ethereum_transactions(self, address: str, limit: int = 10) -> List[Dict]:
        """Get recent Ethereum transactions for an address"""
        try:
            url = f"{self.ethereum_api}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset={limit}&sort=desc"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if data.get('status') != '1':
                return []
            
            transactions = []
            for tx in data.get('result', []):
                transactions.append({
                    'hash': tx.get('hash'),
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'value_wei': int(tx.get('value', '0')),
                    'value_eth': int(tx.get('value', '0')) / 10**18,
                    'gas_used': int(tx.get('gasUsed', '0')),
                    'gas_price': int(tx.get('gasPrice', '0')),
                    'timestamp': int(tx.get('timeStamp', '0')),
                    'confirmations': int(tx.get('confirmations', '0'))
                })
            
            return transactions
            
        except Exception as e:
            return []
    
    def comprehensive_key_and_balance_analysis(self, private_key: int) -> Dict:
        """Comprehensive analysis including Bitcoin and Ethereum balances"""
        try:
            # Get basic key analysis
            analysis = self.comprehensive_key_analysis(private_key)
            
            if 'error' in analysis:
                return analysis
            
            # Generate Ethereum address
            try:
                eth_address = self.private_key_to_ethereum_address(private_key)
                analysis['ethereum_address'] = eth_address
                
                # Get Ethereum balance
                eth_balance = self.get_ethereum_balance(eth_address)
                analysis['ethereum_balance'] = eth_balance
                
                # Get recent Ethereum transactions
                if not eth_balance.get('error'):
                    eth_transactions = self.get_ethereum_transactions(eth_address, 5)
                    analysis['ethereum_transactions'] = eth_transactions
                
            except Exception as e:
                analysis['ethereum_address'] = f"Error: {e}"
                analysis['ethereum_balance'] = {'error': str(e)}
            
            # Enhanced Bitcoin balance information
            total_btc_balance = 0
            active_addresses = []
            
            for key, balance_info in analysis.get('balances', {}).items():
                if not balance_info.get('error') and balance_info.get('balance_btc', 0) > 0:
                    total_btc_balance += balance_info['balance_btc']
                    active_addresses.append({
                        'type': key,
                        'address': analysis['addresses'][key],
                        'balance_btc': balance_info['balance_btc'],
                        'tx_count': balance_info['tx_count']
                    })
            
            analysis['summary'] = {
                'total_btc_balance': total_btc_balance,
                'active_btc_addresses': len(active_addresses),
                'ethereum_balance_eth': analysis.get('ethereum_balance', {}).get('balance_eth', 0),
                'total_value_estimate': f"{total_btc_balance} BTC + {analysis.get('ethereum_balance', {}).get('balance_eth', 0)} ETH"
            }
            
            analysis['active_addresses'] = active_addresses
            
            return analysis
            
        except Exception as e:
            return {'error': f"Comprehensive analysis failed: {e}"}

# Example usage and testing
if __name__ == "__main__":
    utils = BitcoinUtils()
    
    # Test with a known private key (example only - don't use in production)
    test_key = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    
    print("=== Bitcoin Key Analysis ===")
    analysis = utils.comprehensive_key_analysis(test_key)
    
    print(f"Private Key: {analysis['private_key_hex']}")
    print(f"Public Key X: {analysis['public_key']['x']}")
    print(f"Public Key Y: {analysis['public_key']['y']}")
    print(f"Point Valid: {analysis['public_key']['valid_point']}")
    
    print("\nGenerated Addresses:")
    for key, address in analysis['addresses'].items():
        print(f"  {key}: {address}")
    
    print("\nWIF Keys:")
    for key, wif in analysis['wif_keys'].items():
        print(f"  {key}: {wif}")