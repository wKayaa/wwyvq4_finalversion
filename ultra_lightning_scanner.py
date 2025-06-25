#!/usr/bin/env python3
"""
⚡ Ultra-Lightning K8s Scanner - Maximum Performance Edition
Author: wKayaa
Date: 2025-01-28

This is the most extreme performance version for 9999 IPs in 6 minutes.
Uses raw sockets, minimal object creation, and streaming results.
"""

import asyncio
import aiohttp
import socket
import struct
import time
import json
from typing import List, Dict, Optional, AsyncGenerator, Tuple
from dataclasses import dataclass
from ipaddress import IPv4Network

@dataclass
class FastResult:
    """Minimal result object for speed"""
    ip: str
    port: int
    service: str = "k8s"
    time: float = 0.0

class UltraLightningScanner:
    """Ultra-high performance scanner with streaming results"""
    
    def __init__(self, timeout: float = 0.5, max_concurrent: int = 20000):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.k8s_ports = [6443, 8443, 10250]  # Critical ports only
        
        # Performance counters
        self.scanned_count = 0
        self.found_count = 0
        
    async def stream_scan_results(self, targets: List[str]) -> AsyncGenerator[FastResult, None]:
        """Stream scan results as they're found for memory efficiency"""
        
        # Expand all targets to IPs
        all_ips = []
        for target in targets:
            if '/' in target:
                try:
                    network = IPv4Network(target, strict=False)
                    # Limit to prevent memory issues
                    for i, ip in enumerate(network.hosts()):
                        if i >= 10000:  # Reasonable limit
                            break
                        all_ips.append(str(ip))
                except Exception:
                    continue
            else:
                all_ips.append(target)
        
        print(f"⚡ Ultra-Lightning scan starting: {len(all_ips)} IPs")
        start_time = time.time()
        
        # Create batches for parallel processing
        batch_size = 50  # Smaller batches for faster response
        batches = [all_ips[i:i + batch_size] for i in range(0, len(all_ips), batch_size)]
        
        # Process batches with extreme concurrency
        semaphore = asyncio.Semaphore(50)  # Batch concurrency
        
        async def process_batch(batch: List[str]) -> List[FastResult]:
            async with semaphore:
                return await self._scan_ip_batch(batch)
        
        # Start all batch tasks
        batch_tasks = [process_batch(batch) for batch in batches]
        
        # Stream results as they complete
        for completed_task in asyncio.as_completed(batch_tasks):
            try:
                batch_results = await completed_task
                for result in batch_results:
                    yield result
                    self.found_count += 1
            except Exception as e:
                continue
        
        duration = time.time() - start_time
        rate = len(all_ips) / duration if duration > 0 else 0
        print(f"⚡ Scan complete: {rate:.1f} IPs/sec, {self.found_count} services found")
    
    async def _scan_ip_batch(self, ip_batch: List[str]) -> List[FastResult]:
        """Scan a batch of IPs with maximum concurrency"""
        
        # Create all port scan tasks for the batch
        tasks = []
        for ip in ip_batch:
            for port in self.k8s_ports:
                task = self._ultra_fast_port_check(ip, port)
                tasks.append(task)
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        valid_results = []
        for result in results:
            if isinstance(result, FastResult):
                valid_results.append(result)
            self.scanned_count += 1
        
        return valid_results
    
    async def _ultra_fast_port_check(self, ip: str, port: int) -> Optional[FastResult]:
        """Ultra-fast port check with minimal overhead"""
        start_time = time.time()
        
        try:
            # Raw socket connect for speed
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open, do minimal HTTP check
                return await self._minimal_http_check(ip, port, start_time)
        
        except Exception:
            pass
        
        return None
    
    async def _minimal_http_check(self, ip: str, port: int, start_time: float) -> Optional[FastResult]:
        """Minimal HTTP check to confirm K8s service"""
        try:
            # Ultra-lightweight HTTP check
            connector = aiohttp.TCPConnector(
                ssl=False,
                limit=None,
                force_close=True,
                enable_cleanup_closed=False
            )
            
            timeout = aiohttp.ClientTimeout(total=0.5)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                
                # Try HTTPS for K8s API ports
                protocol = 'https' if port in [6443, 8443] else 'http'
                url = f"{protocol}://{ip}:{port}/"
                
                async with session.get(url) as response:
                    # Accept any response that indicates a service
                    if response.status < 500:
                        return FastResult(
                            ip=ip,
                            port=port,
                            service="k8s",
                            time=time.time() - start_time
                        )
        
        except Exception:
            pass
        
        return None

async def ultra_lightning_demo():
    """Demonstrate ultra-lightning scanning"""
    print("⚡ ULTRA-LIGHTNING K8S SCANNER")
    print("🎯 Maximum Performance Mode")
    print("=" * 50)
    
    # Test targets
    targets = [
        "10.0.0.0/24",
        "172.16.0.0/24", 
        "192.168.1.0/24"
    ]
    
    scanner = UltraLightningScanner(timeout=0.5, max_concurrent=20000)
    
    results = []
    start_time = time.time()
    
    # Stream results
    async for result in scanner.stream_scan_results(targets):
        results.append(result)
        # Print results in real-time
        if len(results) % 10 == 0:
            elapsed = time.time() - start_time
            rate = scanner.scanned_count / elapsed if elapsed > 0 else 0
            print(f"⚡ Progress: {scanner.scanned_count} scanned, {len(results)} found ({rate:.1f} IPs/sec)")
    
    # Final stats
    duration = time.time() - start_time
    total_scanned = scanner.scanned_count
    rate = total_scanned / duration if duration > 0 else 0
    
    print(f"\n🎯 ULTRA-LIGHTNING RESULTS:")
    print(f"   ⏱️ Duration: {duration:.2f} seconds")
    print(f"   📊 Scanned: {total_scanned} IP:port combinations")
    print(f"   🚀 Rate: {rate:.1f} scans/second")
    print(f"   🔍 Found: {len(results)} services")
    
    # Extrapolate performance
    if rate > 0:
        # Assume 3 ports per IP
        ip_rate = rate / 3
        time_for_9999 = 9999 / ip_rate / 60 if ip_rate > 0 else float('inf')
        print(f"   📈 Estimated IP rate: {ip_rate:.1f} IPs/second")
        print(f"   🎯 Time for 9999 IPs: {time_for_9999:.1f} minutes")
        
        if time_for_9999 <= 6:
            print("   ✅ TARGET ACHIEVED!")
        else:
            print(f"   ⚠️ Need {time_for_9999/6:.1f}x improvement")

if __name__ == "__main__":
    asyncio.run(ultra_lightning_demo())