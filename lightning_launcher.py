#!/usr/bin/env python3
"""
⚡ Lightning K8s Scanner - Ultra-Fast 6-Minute Scanner
Author: wKayaa
Date: 2025-01-28

Target: 9999 IPs in 6 minutes (28 IPs/second)
"""

import asyncio
import time
import sys
from pathlib import Path
from typing import List

try:
    from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig, ScanMode, ValidationType
except ImportError:
    print("❌ Error: Could not import k8s_scanner_ultimate module")
    print("Make sure all dependencies are installed: pip install aiohttp")
    sys.exit(1)

async def lightning_scan_demo():
    """Demonstrate lightning-fast scanning capabilities"""
    print("⚡ LIGHTNING K8S SCANNER - 6 MINUTE TARGET")
    print("=" * 60)
    print("🎯 Target: 9999 IPs in 6 minutes (28 IPs/second)")
    print("🚀 Mode: LIGHTNING - Ultra-fast with minimal validation")
    print()
    
    # Generate test IP ranges for demonstration
    test_targets = [
        "10.0.0.0/24",    # 254 IPs
        "172.16.0.0/24",  # 254 IPs  
        "192.168.1.0/24", # 254 IPs
        "10.10.0.0/24",   # 254 IPs
    ]
    
    # Create lightning configuration
    config = ScannerConfig.get_lightning_config()
    print(f"⚡ Configuration:")
    print(f"   🔧 Max Concurrent: {config.max_concurrent}")
    print(f"   ⏱️ Timeout: {config.timeout}s")
    print(f"   🎯 Ports: {config.lightning_ports}")
    print(f"   📦 Batch Size: {config.batch_size}")
    print(f"   🔄 Parallel Batches: {config.max_parallel_batches}")
    print(f"   ✅ Validation: {config.validation_type.value}")
    print()
    
    # Initialize scanner
    scanner = K8sUltimateScanner(config)
    
    # Run scan and measure performance
    print("🚀 Starting lightning scan...")
    start_time = time.time()
    
    try:
        results = await scanner.scan_targets(test_targets)
        
        end_time = time.time()
        duration = end_time - start_time
        total_ips = scanner.scan_stats.get("total_ips", 0)
        rate = total_ips / duration if duration > 0 else 0
        
        print("\n⚡ LIGHTNING SCAN RESULTS")
        print("=" * 40)
        print(f"⏱️ Duration: {duration:.2f} seconds")
        print(f"📊 Total IPs: {total_ips}")
        print(f"🚀 Scan Rate: {rate:.1f} IPs/second")
        print(f"🔍 Services Found: {len(results)}")
        print(f"🎯 Success Rate: {len(results)/total_ips*100:.1f}%")
        
        # Performance analysis
        target_rate = 28  # IPs/second for 6-minute target
        if rate >= target_rate:
            print(f"✅ TARGET ACHIEVED! ({rate:.1f} >= {target_rate} IPs/sec)")
        else:
            improvement_needed = target_rate / rate if rate > 0 else float('inf')
            print(f"⚠️ Need {improvement_needed:.1f}x improvement to reach target")
        
        # Extrapolate to 9999 IPs
        if rate > 0:
            time_for_9999 = 9999 / rate / 60  # minutes
            print(f"📈 Estimated time for 9999 IPs: {time_for_9999:.1f} minutes")
        
        # Show found services
        if results:
            print(f"\n🔍 Found Services:")
            for result in results[:5]:  # Show first 5
                print(f"   🎯 {result.target_ip}:{result.port} - {result.service}")
            if len(results) > 5:
                print(f"   ... and {len(results) - 5} more")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        import traceback
        traceback.print_exc()

async def custom_lightning_scan(targets: List[str]):
    """Run lightning scan on custom targets"""
    config = ScannerConfig.get_lightning_config()
    scanner = K8sUltimateScanner(config)
    
    print(f"⚡ Starting lightning scan on {len(targets)} targets...")
    start_time = time.time()
    
    results = await scanner.scan_targets(targets)
    
    duration = time.time() - start_time
    total_ips = scanner.scan_stats.get("total_ips", 0)
    rate = total_ips / duration if duration > 0 else 0
    
    print(f"✅ Completed: {total_ips} IPs in {duration:.1f}s ({rate:.1f} IPs/sec)")
    return results

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Custom targets provided
        targets = sys.argv[1:]
        asyncio.run(custom_lightning_scan(targets))
    else:
        # Run demo
        asyncio.run(lightning_scan_demo())