#!/usr/bin/env python3
"""
🎯 Ultimate 6-Minute Scanner - 9999 IPs in 6 Minutes
Author: wKayaa
Date: 2025-01-28

The final implementation to achieve the 6-minute target for 9999 IPs.
Uses all available optimizations and hyper-lightning mode.
"""

import asyncio
import time
import sys
import os
import resource
from pathlib import Path
from typing import List, Dict, Any

def optimize_system():
    """Apply system-level optimizations for maximum performance"""
    print("🔧 Applying system optimizations...")
    
    try:
        # Increase file descriptor limit
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_limit = min(100000, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard))
        print(f"   📁 File descriptors: {new_limit}")
    except Exception as e:
        print(f"   ⚠️ Could not set file descriptors: {e}")
    
    try:
        # Set process priority
        os.nice(-5)  # Higher priority
        print("   ⬆️ Process priority increased")
    except Exception:
        print("   ⚠️ Could not increase process priority")

def generate_target_ranges(count: int = 9999) -> List[str]:
    """Generate target IP ranges for testing"""
    # Generate efficient CIDR ranges to cover ~9999 IPs
    ranges = []
    
    # Use /24 networks (254 IPs each)
    networks_needed = (count + 253) // 254  # Round up
    
    # Common internal networks
    base_networks = [
        "10.0.",
        "10.10.",
        "10.20.",
        "172.16.",
        "172.17.",
        "172.18.",
        "192.168.",
        "10.96.",   # K8s service networks
        "10.244.",  # K8s pod networks
    ]
    
    network_count = 0
    for base in base_networks:
        if network_count >= networks_needed:
            break
        
        for subnet in range(0, 256):
            if network_count >= networks_needed:
                break
            
            ranges.append(f"{base}{subnet}.0/24")
            network_count += 1
    
    return ranges[:networks_needed]

async def six_minute_challenge():
    """Run the 6-minute challenge: 9999 IPs in 6 minutes"""
    print("🎯 6-MINUTE CHALLENGE: 9999 IPs in 6 MINUTES")
    print("=" * 60)
    print("🚀 Target: 28 IPs/second sustained performance")
    print("⚡ Mode: HYPER-LIGHTNING with all optimizations")
    print()
    
    # System optimizations
    optimize_system()
    print()
    
    # Generate targets
    target_ranges = generate_target_ranges(9999)
    print(f"🎯 Generated {len(target_ranges)} CIDR ranges")
    print(f"📊 Estimated IPs: {len(target_ranges) * 254}")
    print()
    
    # Import and configure scanner
    try:
        from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig
        
        # Use hyper-lightning configuration
        config = ScannerConfig.get_hyper_lightning_config()
        print(f"⚡ HYPER-LIGHTNING Configuration:")
        print(f"   🔧 Concurrency: {config.max_concurrent}")
        print(f"   ⏱️ Timeout: {config.timeout}s")
        print(f"   🎯 Ports: {config.lightning_ports}")
        print(f"   📦 Batch size: {config.batch_size}")
        print(f"   🔄 Parallel batches: {config.max_parallel_batches}")
        print()
        
        # Create scanner
        scanner = K8sUltimateScanner(config)
        
        # Start the challenge
        print("🚀 STARTING 6-MINUTE CHALLENGE...")
        print("⏱️ Timer starts NOW!")
        
        start_time = time.time()
        target_time = 6 * 60  # 6 minutes in seconds
        
        # Run scan with timeout
        try:
            results = await asyncio.wait_for(
                scanner.scan_targets(target_ranges),
                timeout=target_time + 10  # 10 second grace period
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Calculate results
            total_ips = scanner.scan_stats.get("total_ips", len(target_ranges) * 254)
            rate = total_ips / duration if duration > 0 else 0
            
            print(f"\n🎯 6-MINUTE CHALLENGE RESULTS:")
            print("=" * 40)
            print(f"⏱️ Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
            print(f"📊 Total IPs: {total_ips}")
            print(f"🚀 Rate: {rate:.1f} IPs/second")
            print(f"🔍 Services found: {len(results)}")
            print(f"💯 Success rate: {len(results)/total_ips*100:.2f}%")
            
            # Challenge evaluation
            target_rate = 28  # IPs/second
            if duration <= target_time and rate >= target_rate:
                print(f"✅ CHALLENGE COMPLETED! ({rate:.1f} >= {target_rate} IPs/sec in {duration/60:.1f} minutes)")
                print("🏆 6-MINUTE TARGET ACHIEVED!")
            elif duration <= target_time:
                print(f"⚠️ Time target met but rate too low ({rate:.1f} < {target_rate} IPs/sec)")
            elif rate >= target_rate:
                print(f"⚠️ Rate target met but took too long ({duration/60:.1f} > 6 minutes)")
            else:
                print(f"❌ Challenge not completed")
                print(f"   📊 Rate: {rate:.1f} IPs/sec (need {target_rate})")
                print(f"   ⏱️ Time: {duration/60:.1f} min (need 6)")
            
            # Performance analysis
            if total_ips >= 9999:
                actual_9999_time = 9999 / rate / 60 if rate > 0 else float('inf')
                print(f"\n📈 9999 IP Performance:")
                print(f"   🎯 Estimated time for 9999 IPs: {actual_9999_time:.1f} minutes")
                
                if actual_9999_time <= 6:
                    print("   ✅ 9999 IPs in 6 minutes: ACHIEVABLE!")
                else:
                    improvement = actual_9999_time / 6
                    print(f"   ⚠️ Need {improvement:.1f}x improvement for 6-minute target")
            
            return results
            
        except asyncio.TimeoutError:
            print(f"\n⏰ Challenge timed out after 6 minutes!")
            print("❌ 6-minute target not achieved")
            return []
    
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all dependencies are installed")
        return []
    
    except Exception as e:
        print(f"❌ Challenge failed: {e}")
        import traceback
        traceback.print_exc()
        return []

async def quick_demo():
    """Run a quick demo with fewer IPs"""
    print("⚡ QUICK DEMO - Lightning Performance Test")
    print("=" * 50)
    
    # Smaller test for quick validation
    test_ranges = [
        "10.0.0.0/24",
        "172.16.0.0/24",
        "192.168.1.0/24"
    ]
    
    try:
        from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig
        
        config = ScannerConfig.get_lightning_config()
        scanner = K8sUltimateScanner(config)
        
        print(f"🎯 Testing {len(test_ranges)} networks...")
        
        start_time = time.time()
        results = await scanner.scan_targets(test_ranges)
        duration = time.time() - start_time
        
        total_ips = scanner.scan_stats.get("total_ips", len(test_ranges) * 254)
        rate = total_ips / duration if duration > 0 else 0
        
        print(f"\n⚡ Demo Results:")
        print(f"   📊 {total_ips} IPs in {duration:.1f}s ({rate:.1f} IPs/sec)")
        print(f"   🔍 {len(results)} services found")
        
        # Extrapolate to 9999 IPs
        if rate > 0:
            time_for_9999 = 9999 / rate / 60
            print(f"   📈 Estimated time for 9999 IPs: {time_for_9999:.1f} minutes")
        
        return results
        
    except ImportError:
        print("❌ Scanner module not available for demo")
        return []

def main():
    """Main launcher"""
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        return asyncio.run(quick_demo())
    else:
        return asyncio.run(six_minute_challenge())

if __name__ == "__main__":
    main()