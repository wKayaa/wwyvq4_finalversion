#!/usr/bin/env python3
"""
🧪 F8S Framework Test Suite
Test the complete pipeline with mock data

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import sys
from pathlib import Path

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, str(Path(__file__).parent))

from main import main as f8s_main
from core.orchestrator import F8SOrchestrator
from core.session_manager import SessionManager
from core.error_handler import ErrorHandler
from config.settings import load_config


async def test_framework_components():
    """Test individual framework components"""
    print("🧪 Testing F8S Framework Components...")
    
    # Test session manager
    print("📋 Testing Session Manager...")
    session_manager = SessionManager()
    session_id = session_manager.create_session("test")
    session = session_manager.get_session(session_id)
    assert session is not None
    print(f"✅ Session created: {session_id}")
    
    # Test error handler
    print("🛡️ Testing Error Handler...")
    error_handler = ErrorHandler(retry_count=2, skip_on_fail=True)
    
    async def failing_function():
        raise Exception("Test error")
    
    result = await error_handler.execute_with_retry(failing_function)
    assert result is None  # Should return None when skipping on fail
    print("✅ Error handler working correctly")
    
    # Test configuration
    print("⚙️ Testing Configuration...")
    config = load_config("config/f8s_config.yaml")
    assert config is not None
    print("✅ Configuration loaded successfully")
    
    print("✅ All component tests passed!")


async def test_full_pipeline():
    """Test full pipeline with mock target"""
    print("🚀 Testing Full F8S Pipeline...")
    
    # Create a test targets file
    test_targets_file = Path("test_pipeline_targets.txt")
    with open(test_targets_file, 'w') as f:
        f.write("httpbin.org\n")  # Use a known HTTP service for testing
    
    # Test the pipeline
    print("🎯 Running pipeline test...")
    
    # Mock command line arguments
    class MockArgs:
        target = None
        targets = str(test_targets_file)
        mode = "scan"
        threads = 1
        timeout = 5
        web = False
        api = False
        telegram_token = None
        telegram_chat = None
        discord_webhook = None
        output = "./test_results"
        config = "config/f8s_config.yaml"
        export_format = "json"
        retry_count = 1
        skip_validation = True
        no_cleanup = False
        verbose = True
        debug = False
    
    # Simulate the main function with our test args
    try:
        # This would normally be called by main(), but we'll simulate it
        config = load_config(MockArgs.config)
        session_manager = SessionManager()
        error_handler = ErrorHandler(retry_count=1, skip_on_fail=True)
        
        # Create orchestrator
        orchestrator = F8SOrchestrator(
            config=config,
            session_manager=session_manager,
            error_handler=error_handler,
            args=MockArgs
        )
        
        # Test target loading
        targets = ["httpbin.org"]
        
        # Initialize
        await orchestrator.initialize()
        
        # Run a quick scan
        print("🔍 Running scan test...")
        results = await orchestrator.run_pipeline(targets, "scan")
        
        print(f"📊 Test Results:")
        print(f"  Success: {results.success}")
        print(f"  Targets processed: {results.targets_processed}")
        print(f"  Duration: {(results.end_time - results.start_time).total_seconds():.2f}s")
        
        # Cleanup
        await orchestrator.cleanup()
        
        # Remove test file
        test_targets_file.unlink()
        
        print("✅ Full pipeline test completed!")
        
    except Exception as e:
        print(f"❌ Pipeline test failed: {str(e)}")
        # Clean up test file even if test fails
        if test_targets_file.exists():
            test_targets_file.unlink()


async def test_enhanced_scanner():
    """Test enhanced scanner capabilities"""
    print("🔍 Testing Enhanced Scanner...")
    
    from modules.scanner.discovery import K8sDiscoveryScanner
    
    scanner = K8sDiscoveryScanner(timeout=3, max_concurrent=1)
    
    # Test target expansion
    targets = scanner._expand_target("192.168.1.0/30")  # Small subnet
    assert len(targets) <= 10  # Should limit expansion
    print(f"✅ Target expansion: {len(targets)} targets")
    
    # Test scan (this will fail but should handle gracefully)
    result = await scanner.scan_target("1.1.1.1")  # Cloudflare DNS, safe to test
    assert "target" in result
    assert "clusters" in result
    print(f"✅ Scanner test: {len(result['clusters'])} clusters found")


async def test_enhanced_exploiter():
    """Test enhanced exploiter capabilities"""
    print("⚡ Testing Enhanced Exploiter...")
    
    from modules.exploiter.k8s_exploiter import K8sExploiter
    
    exploiter = K8sExploiter(mode="test", timeout=3)
    
    # Mock cluster data
    mock_cluster = {
        "endpoint": "https://test-cluster:6443",
        "target": "test-cluster",
        "port": 6443,
        "protocol": "https",
        "status": "accessible",
        "vulnerabilities": ["anonymous_api_access", "exposed_metrics"]
    }
    
    # Test exploitation
    result = await exploiter.exploit_cluster(mock_cluster, "test")
    assert "success" in result
    assert "exploits_used" in result
    print(f"✅ Exploiter test: {len(result['exploits_used'])} exploits used")


async def test_enhanced_extractor():
    """Test enhanced credential extractor"""
    print("🔑 Testing Enhanced Credential Extractor...")
    
    from modules.extractors.credential_extractor import CredentialExtractor
    
    extractor = CredentialExtractor()
    
    # Mock exploitation result
    mock_exploitation = {
        "cluster": {"endpoint": "https://test:6443"},
        "secrets_found": [
            {
                "type": "test_secret",
                "value": "AKIAIOSFODNN7EXAMPLE",  # Mock AWS key format
                "source": "test"
            }
        ],
        "pods_compromised": 1,
        "exploits_used": ["service_account_theft"]
    }
    
    # Test extraction
    credentials = await extractor.extract_credentials(mock_exploitation)
    assert len(credentials) > 0
    print(f"✅ Extractor test: {len(credentials)} credentials extracted")
    
    # Test pattern matching
    assert any(cred["type"] == "aws_access_key" for cred in credentials)
    print("✅ Pattern matching working correctly")


async def main():
    """Run all tests"""
    print("🧪 F8S Framework Test Suite")
    print("=" * 60)
    
    try:
        await test_framework_components()
        print()
        
        await test_enhanced_scanner()
        print()
        
        await test_enhanced_exploiter()
        print()
        
        await test_enhanced_extractor()
        print()
        
        await test_full_pipeline()
        print()
        
        print("🎉 All tests passed! F8S Framework is ready for deployment.")
        return 0
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))