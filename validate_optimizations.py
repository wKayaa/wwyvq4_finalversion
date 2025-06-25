#!/usr/bin/env python3
"""
🧪 WWYVQ Large Scale Validation Suite
Quick validation of all optimization components

Author: wKayaa
Date: 2025-01-17
"""

import sys
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all optimized components can be imported"""
    print("🔧 Testing component imports...")
    
    try:
        from config.config_loader import ConfigurationLoader, load_optimized_config
        print("  ✅ Configuration loader")
        
        from utils.rate_limiter import AdaptiveRateLimiter, RateLimitConfig, TokenBucket
        print("  ✅ Rate limiter")
        
        # Test enhanced components exist
        import k8s_scanner_ultimate
        print("  ✅ K8s Ultimate Scanner")
        
        import telegram_mail_enhanced
        print("  ✅ Enhanced Telegram notifier")
        
        import wwyvq_master_final
        print("  ✅ Master framework")
        
        return True
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False

def test_configuration():
    """Test configuration loading and scaling"""
    print("\n📊 Testing configuration scaling...")
    
    try:
        from config.config_loader import ConfigurationLoader
        
        loader = ConfigurationLoader()
        
        # Test different scales
        test_counts = [10000, 100000, 1000000, 16000000]
        
        for count in test_counts:
            recommendations = loader.get_system_recommendations(count)
            print(f"  ✅ {count:,} targets: {recommendations['cpu_cores']} CPU, {recommendations['memory_gb']} GB RAM")
        
        # Test system validation
        validation = loader.validate_system_configuration()
        print(f"  ℹ️ System validation: {len([k for k, v in validation.items() if v])} checks passed")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Configuration error: {e}")
        return False

def test_rate_limiter():
    """Test rate limiting functionality"""
    print("\n⏱️ Testing rate limiter...")
    
    try:
        from utils.rate_limiter import AdaptiveRateLimiter, RateLimitConfig
        
        config = RateLimitConfig(
            max_requests_per_second=10,
            max_burst=20,
            adaptive_mode=True
        )
        
        limiter = AdaptiveRateLimiter(config)
        print("  ✅ Rate limiter created")
        
        stats = limiter.get_stats()
        print(f"  ✅ Statistics: {stats['current_delay']:.3f}s delay, {stats['available_permits']} permits")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Rate limiter error: {e}")
        return False

async def test_telegram_config():
    """Test Telegram configuration"""
    print("\n📱 Testing Telegram configuration...")
    
    try:
        from telegram_mail_enhanced import TelegramMailNotifier, TelegramRateLimitConfig
        
        config = TelegramRateLimitConfig(
            max_messages_per_minute=20,
            batch_size=100,
            enable_batching=True
        )
        
        notifier = TelegramMailNotifier(
            token="test_token",
            chat_id="test_chat",
            config=config
        )
        notifier.enabled = False  # Disable for testing
        
        print("  ✅ Telegram notifier created")
        
        stats = notifier.get_rate_limit_stats()
        print(f"  ✅ Rate limit stats: batch_size={stats['config']['batch_size']}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Telegram error: {e}")
        return False

def test_large_scale_config():
    """Test large scale configuration file"""
    print("\n📋 Testing large scale configuration...")
    
    try:
        config_file = Path("config/large_scale_config.yaml")
        
        if config_file.exists():
            print("  ✅ Large scale config file exists")
            
            # Try to load it
            import yaml
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Check key sections
            required_sections = ['system', 'network', 'scanning', 'telegram', 'monitoring']
            for section in required_sections:
                if section in config_data:
                    print(f"  ✅ Section '{section}' present")
                else:
                    print(f"  ⚠️ Section '{section}' missing")
            
            # Check key values
            max_concurrent = config_data.get('system', {}).get('max_concurrent_threads', 0)
            print(f"  ℹ️ Max concurrent threads: {max_concurrent:,}")
            
            return True
        else:
            print("  ❌ Large scale config file not found")
            return False
            
    except Exception as e:
        print(f"  ❌ Config file error: {e}")
        return False

def test_file_structure():
    """Test file structure and permissions"""
    print("\n📁 Testing file structure...")
    
    files_to_check = [
        "k8s_scanner_ultimate.py",
        "telegram_mail_enhanced.py", 
        "wwyvq_master_final.py",
        "config/config_loader.py",
        "config/large_scale_config.yaml",
        "utils/rate_limiter.py",
        "large_scale_demo.py",
        "setup_large_scale.sh"
    ]
    
    missing_files = []
    
    for file_path in files_to_check:
        if Path(file_path).exists():
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path}")
            missing_files.append(file_path)
    
    # Check script permissions
    setup_script = Path("setup_large_scale.sh")
    if setup_script.exists() and setup_script.stat().st_mode & 0o111:
        print("  ✅ Setup script is executable")
    elif setup_script.exists():
        print("  ⚠️ Setup script exists but not executable")
    
    return len(missing_files) == 0

async def run_validation():
    """Run all validation tests"""
    print("🚀 WWYVQ Large Scale Optimization Validation")
    print("=" * 50)
    
    results = {}
    
    # Run tests
    results['imports'] = test_imports()
    results['configuration'] = test_configuration()
    results['rate_limiter'] = test_rate_limiter()
    results['telegram'] = await test_telegram_config()
    results['config_file'] = test_large_scale_config()
    results['file_structure'] = test_file_structure()
    
    # Summary
    print("\n📊 VALIDATION SUMMARY")
    print("=" * 30)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All optimizations validated successfully!")
        print("🚀 System ready for large-scale operations (16M+ targets)")
    else:
        print(f"\n⚠️ {total - passed} validation issues found")
        print("💡 Review the failed tests and ensure all components are properly installed")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = asyncio.run(run_validation())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️ Validation interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation error: {e}")
        sys.exit(1)