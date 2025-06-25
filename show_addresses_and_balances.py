
#!/usr/bin/env python3
"""
Show all Bitcoin address types and their balances for a recovered private key
"""

from bitcoin_utils import BitcoinUtils
import time

def show_all_addresses_and_balances(private_key_hex: str):
    """
    Show all Bitcoin address types and their balances for the recovered private key
    """
    print(f"\n{'='*80}")
    print(f"RECOVERED PRIVATE KEY ANALYSIS")
    print(f"{'='*80}")
    
    # Remove 0x prefix if present
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]
    
    # Convert to integer
    private_key = int(private_key_hex, 16)
    
    # Initialize Bitcoin utilities
    bitcoin_utils = BitcoinUtils()
    
    print(f"Private Key (Hex): {private_key_hex}")
    print(f"Private Key (Decimal): {private_key}")
    
    # Get comprehensive analysis with balances
    try:
        analysis = bitcoin_utils.comprehensive_key_and_balance_analysis(private_key)
        
        if 'error' in analysis:
            print(f"Error: {analysis['error']}")
            return
        
        print(f"\n{'='*60}")
        print(f"BITCOIN ADDRESSES AND BALANCES")
        print(f"{'='*60}")
        
        total_btc = 0
        
        # Show all Bitcoin address types
        address_types = [
            ('compressed_mainnet', 'P2PKH Compressed (Mainnet)'),
            ('uncompressed_mainnet', 'P2PKH Uncompressed (Mainnet)'),
            ('compressed_testnet', 'P2PKH Compressed (Testnet)'),
            ('uncompressed_testnet', 'P2PKH Uncompressed (Testnet)')
        ]
        
        for addr_type, description in address_types:
            if addr_type in analysis['addresses']:
                address = analysis['addresses'][addr_type]
                
                if not address.startswith('Error:'):
                    print(f"\n{description}:")
                    print(f"Address: {address}")
                    
                    # Show WIF key
                    if addr_type in analysis['wif_keys']:
                        wif = analysis['wif_keys'][addr_type]
                        print(f"WIF Key: {wif}")
                    
                    # Show balance if available
                    if addr_type in analysis.get('balances', {}):
                        balance_info = analysis['balances'][addr_type]
                        
                        if 'error' not in balance_info:
                            balance_btc = balance_info.get('balance_btc', 0)
                            balance_sat = balance_info.get('balance_satoshis', 0)
                            tx_count = balance_info.get('tx_count', 0)
                            
                            print(f"Balance: {balance_btc:.8f} BTC ({balance_sat:,} satoshis)")
                            print(f"Transaction Count: {tx_count}")
                            
                            if balance_btc > 0:
                                total_btc += balance_btc
                                print(f"⚠️  ACTIVE ADDRESS WITH FUNDS!")
                                
                                # Get recent transactions
                                try:
                                    transactions = bitcoin_utils.get_address_transactions(address, 5)
                                    if transactions:
                                        print("Recent Transactions:")
                                        for i, tx in enumerate(transactions[:3], 1):
                                            print(f"  {i}. {tx['txid'][:16]}... ({tx['value_out']/100000000:.8f} BTC)")
                                except Exception as e:
                                    print(f"  Error fetching transactions: {e}")
                            else:
                                print("Status: Empty")
                        else:
                            print(f"Balance Check Error: {balance_info['error']}")
                    
                    print(f"Explorer: https://blockstream.info/address/{address}")
                else:
                    print(f"\n{description}:")
                    print(f"Error: {address}")
        
        # Show Ethereum address and balance
        print(f"\n{'='*60}")
        print(f"ETHEREUM ADDRESS AND BALANCE")
        print(f"{'='*60}")
        
        if 'ethereum_address' in analysis:
            eth_address = analysis['ethereum_address']
            print(f"Ethereum Address: {eth_address}")
            
            if 'ethereum_balance' in analysis and 'error' not in analysis['ethereum_balance']:
                eth_balance = analysis['ethereum_balance']
                balance_eth = eth_balance.get('balance_eth', 0)
                tx_count = eth_balance.get('tx_count', 0)
                
                print(f"Balance: {balance_eth:.8f} ETH")
                print(f"Transaction Count: {tx_count}")
                
                if balance_eth > 0:
                    print(f"⚠️  ACTIVE ETHEREUM ADDRESS WITH FUNDS!")
                else:
                    print("Status: Empty")
                
                print(f"Explorer: https://etherscan.io/address/{eth_address}")
            else:
                print("Balance check failed or not available")
        
        # Summary
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        
        if 'summary' in analysis:
            summary = analysis['summary']
            print(f"Total Bitcoin Balance: {summary.get('total_btc_balance', 0):.8f} BTC")
            print(f"Active Bitcoin Addresses: {summary.get('active_btc_addresses', 0)}")
            print(f"Ethereum Balance: {summary.get('ethereum_balance_eth', 0):.8f} ETH")
            
            if summary.get('total_btc_balance', 0) > 0 or summary.get('ethereum_balance_eth', 0) > 0:
                print(f"\n🚨 CRITICAL: FUNDS DETECTED!")
                print(f"This private key controls active wallets with cryptocurrency!")
                print(f"Total Value: {summary.get('total_value_estimate', 'Unknown')}")
        
        # Security warning
        print(f"\n{'='*60}")
        print(f"SECURITY WARNING")
        print(f"{'='*60}")
        print("⚠️  Keep this private key secure!")
        print("⚠️  Anyone with this key can control the associated funds!")
        print("⚠️  This demonstrates the importance of proper nonce generation!")
        
    except Exception as e:
        print(f"Error during analysis: {e}")

def main():
    """
    Main function to demonstrate with the recovered private key
    """
    # The recovered private key from the nonce reuse attack
    recovered_private_key = "0x67ed7b38c13a5ab630d608ad994e4a9d0ef2f5161c4f31b1c6fb299c44d8cf47"
    
    print("Analyzing recovered private key from ECDSA nonce reuse attack...")
    show_all_addresses_and_balances(recovered_private_key)

if __name__ == "__main__":
    main()
