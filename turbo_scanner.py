#!/usr/bin/env python3
"""
🚀 K8s Turbo Scanner - Optimized for 6-Hour Completion
Author: wKayaa
Date: 2025-01-17

Ultra-fast Kubernetes security scanner optimized for:
- 28+ IPs/minute throughput
- 5000 concurrent connections
- Parallel port scanning
- Minimal checkpoint overhead
- Critical K8s ports only (6443, 8443, 10250)
"""

import asyncio
import sys
from pathlib import Path
from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig, ScanMode, ValidationType

async def run_turbo_scan(targets_file: str, output_dir: str = "./turbo_results"):
    """Run optimized turbo scan for 6-hour completion"""
    
    # Load targets
    if not Path(targets_file).exists():
        print(f"❌ Targets file not found: {targets_file}")
        return
    
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"🎯 Loaded {len(targets)} targets from {targets_file}")
    
    # Configure for maximum performance
    config = ScannerConfig(
        mode=ScanMode.TURBO,
        max_concurrent=100,  # Base concurrency
        turbo_max_concurrent=5000,  # Turbo concurrency
        timeout=15,  # Base timeout
        turbo_timeout=3,  # Turbo timeout
        validation_type=ValidationType.NONE,  # Skip validation for speed
        enable_checkpoint=True,
        checkpoint_interval=100,  # Base checkpoint interval
        turbo_checkpoint_interval=500,  # Turbo checkpoint interval
        output_dir=Path(output_dir),
        turbo_connector_limit=5000,
        turbo_connector_limit_per_host=1000,
        turbo_ports=[6443, 8443, 10250]  # Critical K8s ports only
    )
    
    print("🚀 TURBO MODE CONFIGURATION:")
    print(f"   ⚡ Max Concurrent: {config.turbo_max_concurrent}")
    print(f"   ⏱️  Timeout: {config.turbo_timeout}s")
    print(f"   🔗 Connector Limit: {config.turbo_connector_limit}")
    print(f"   🎯 Ports: {config.turbo_ports}")
    print(f"   💾 Checkpoint Interval: {config.turbo_checkpoint_interval}")
    print(f"   🎯 Target: 28 IPs/minute for 6-hour completion")
    
    # Run scanner
    scanner = K8sUltimateScanner(config)
    
    print(f"\n🚀 Starting TURBO scan of {len(targets)} targets...")
    print("📊 Expected performance: 28+ IPs/minute")
    print("⏰ Target completion: ~6 hours for 9999 IPs\n")
    
    results = await scanner.scan_targets(targets)
    
    print(f"\n✅ TURBO scan completed!")
    print(f"📊 Results: {len(results)} services found")
    print(f"📁 Output directory: {output_dir}")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python turbo_scanner.py <targets_file> [output_dir]")
        print("Example: python turbo_scanner.py targets.txt ./turbo_results")
        sys.exit(1)
    
    targets_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./turbo_results"
    
    asyncio.run(run_turbo_scan(targets_file, output_dir))

if __name__ == "__main__":
    main()