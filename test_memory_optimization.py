#!/usr/bin/env python3
"""
🧪 Memory Optimization Test Suite
Test the new chunked processing and memory management features

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import sys
import time
import tempfile
import os
from pathlib import Path

# Add project root to path
sys.path.append('.')

from utils.memory_manager import MemoryManager
from utils.target_expander import TargetExpander
from utils.result_writer import ResultWriter


async def test_memory_manager():
    """Test memory manager functionality"""
    print("🧠 Testing Memory Manager...")
    
    memory_manager = MemoryManager()
    
    # Test memory info
    config = memory_manager.get_memory_info()
    print(f"✅ Memory Config: {config.total_memory_gb:.1f}GB total, chunk size: {config.recommended_chunk_size:,}")
    
    # Test memory monitoring
    usage, warning = memory_manager.check_memory_usage()
    print(f"✅ Memory Usage: {usage:.1f}% (warning: {warning})")
    
    # Test adaptive chunk sizing
    chunk_size = memory_manager.get_adaptive_chunk_size(1000000)
    print(f"✅ Adaptive chunk size for 1M targets: {chunk_size:,}")
    
    return True


async def test_target_expander():
    """Test target expander with chunked processing"""
    print("🎯 Testing Target Expander...")
    
    expander = TargetExpander()
    
    # Test memory estimation
    test_targets = ["192.168.1.0/24", "10.0.0.0/16", "127.0.0.1"]
    total_count, estimated_mb = expander.estimate_memory_usage(test_targets)
    print(f"✅ Memory estimation: {total_count:,} targets, ~{estimated_mb:.1f} MB")
    
    # Test generator (should not consume much memory)
    print("🔄 Testing generator expansion...")
    count = 0
    start_time = time.time()
    
    for target in expander.expand_targets_generator(["192.168.1.0/28"]):  # Small subnet
        count += 1
        if count > 20:  # Limit for test
            break
    
    elapsed = time.time() - start_time
    print(f"✅ Generator test: {count} targets in {elapsed:.3f}s")
    
    # Test chunked expansion
    print("📦 Testing chunked expansion...")
    chunk_count = 0
    total_targets = 0
    
    for chunk in expander.expand_targets_chunked(["192.168.1.0/26"], chunk_size=10):
        chunk_count += 1
        total_targets += len(chunk)
        print(f"  Chunk {chunk_count}: {len(chunk)} targets")
        if chunk_count >= 5:  # Limit for test
            break
    
    print(f"✅ Chunked test: {chunk_count} chunks, {total_targets} total targets")
    
    return True


async def test_result_writer():
    """Test result writer for streaming output"""
    print("📝 Testing Result Writer...")
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Test result writer
        with ResultWriter(temp_path, "test_session", compress=False) as writer:
            
            # Write test results
            for i in range(100):
                test_result = {
                    "target_ip": f"192.168.1.{i}",
                    "port": 443,
                    "service": "kubernetes" if i % 10 == 0 else "unknown",
                    "credentials": [{"type": "token", "value": f"token_{i}"}] if i % 20 == 0 else [],
                    "timestamp": time.time()
                }
                writer.write_result(test_result)
            
            # Write stats
            writer.write_stats({"total_processed": 100, "success_rate": 0.15})
        
        # Check files were created
        files = list(temp_path.glob("*"))
        print(f"✅ Created {len(files)} output files:")
        for file in files:
            size_kb = file.stat().st_size / 1024
            print(f"  {file.name}: {size_kb:.1f} KB")
    
    return True


async def test_large_target_simulation():
    """Simulate processing of large target set"""
    print("🚀 Testing Large Target Set Simulation...")
    
    # Create a simulated large CIDR that would expand to many IPs
    large_targets = ["10.0.0.0/16"]  # 65536 IPs
    
    expander = TargetExpander()
    memory_manager = MemoryManager()
    
    # Test memory estimation
    total_count, estimated_mb = expander.estimate_memory_usage(large_targets)
    print(f"📊 Large target estimation: {total_count:,} targets, ~{estimated_mb:.1f} MB")
    
    # Test adaptive chunk sizing
    adaptive_chunk = memory_manager.get_adaptive_chunk_size(total_count)
    print(f"📦 Recommended chunk size: {adaptive_chunk:,} targets")
    
    # Test chunked processing (limited for test)
    print("🔄 Testing chunked processing (limited)...")
    
    chunk_count = 0
    processed_targets = 0
    start_time = time.time()
    
    for chunk in expander.expand_targets_chunked(large_targets, chunk_size=1000):
        chunk_count += 1
        processed_targets += len(chunk)
        
        # Simulate processing time
        await asyncio.sleep(0.01)
        
        if chunk_count >= 5:  # Limit for test
            print(f"  Stopping at chunk {chunk_count} for test purposes...")
            break
        
        print(f"  Processed chunk {chunk_count}: {len(chunk):,} targets")
    
    elapsed = time.time() - start_time
    print(f"✅ Chunked simulation: {chunk_count} chunks, {processed_targets:,} targets in {elapsed:.3f}s")
    
    # Calculate projected performance
    targets_per_second = processed_targets / elapsed
    estimated_full_time = total_count / targets_per_second
    print(f"📈 Projected: {targets_per_second:,.0f} targets/sec, {estimated_full_time/3600:.1f} hours for full set")
    
    return True


async def test_oom_prevention():
    """Test OOM prevention mechanisms"""
    print("🛡️ Testing OOM Prevention...")
    
    memory_manager = MemoryManager()
    
    # Test memory monitoring during simulated load
    print("🔄 Simulating memory load...")
    
    # Simulate creating large data structures
    test_data = []
    for i in range(5):
        # Monitor memory before allocation
        before_stats = memory_manager.monitor_memory_during_processing()
        print(f"  Before iteration {i+1}: {before_stats['system_memory_percent']:.1f}% system")
        
        # Create some test data (simulate scan results)
        batch_data = [f"target_{j}" for j in range(10000)]
        test_data.extend(batch_data)
        
        # Monitor after allocation
        after_stats = memory_manager.monitor_memory_during_processing()
        print(f"  After iteration {i+1}: {after_stats['system_memory_percent']:.1f}% system")
        
        # Test cleanup
        if i == 2:  # Force cleanup midway
            memory_manager.force_cleanup()
            cleanup_stats = memory_manager.monitor_memory_during_processing()
            print(f"  After cleanup: {cleanup_stats['system_memory_percent']:.1f}% system")
    
    # Final cleanup
    del test_data
    memory_manager.force_cleanup()
    
    final_stats = memory_manager.monitor_memory_during_processing()
    print(f"✅ Final memory: {final_stats['system_memory_percent']:.1f}% system")
    
    return True


async def main():
    """Run all memory optimization tests"""
    print("🧪 WWYVQ Memory Optimization Test Suite")
    print("=" * 50)
    
    tests = [
        ("Memory Manager", test_memory_manager),
        ("Target Expander", test_target_expander),
        ("Result Writer", test_result_writer),
        ("Large Target Simulation", test_large_target_simulation),
        ("OOM Prevention", test_oom_prevention)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔬 Running {test_name} Test...")
        try:
            success = await test_func()
            results.append((test_name, success))
            print(f"✅ {test_name}: PASSED")
        except Exception as e:
            results.append((test_name, False))
            print(f"❌ {test_name}: FAILED - {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY:")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"  {test_name}: {status}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🚀 All memory optimizations working correctly!")
        return 0
    else:
        print("⚠️ Some tests failed - review implementation")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)