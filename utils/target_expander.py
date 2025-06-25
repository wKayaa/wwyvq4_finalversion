#!/usr/bin/env python3
"""
🎯 Target Expander with Memory Optimization
Expand target specifications (CIDR, ranges, etc.) using generators for memory efficiency

Author: wKayaa
Date: 2025-01-28
"""

import ipaddress
import logging
from typing import List, Iterator, Generator, Tuple, Optional
from .memory_manager import MemoryManager


class TargetExpander:
    """Memory-efficient target specifications expander"""
    
    def __init__(self):
        self.memory_manager = MemoryManager()
        self.logger = logging.getLogger("TargetExpander")
    
    async def expand_targets(self, targets: List[str]) -> List[str]:
        """Legacy method for backward compatibility - loads all targets into memory"""
        self.logger.warning("⚠️ Using legacy expand_targets - may cause OOM for large target sets")
        expanded = []
        
        for target in targets:
            try:
                # Check if it's a CIDR range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    # Limit expansion for very large networks
                    if network.num_addresses > 100000:
                        self.logger.warning(f"⚠️ Large network {target} - limiting to first 100K IPs")
                        for i, ip in enumerate(network.hosts()):
                            if i >= 100000:
                                break
                            expanded.append(str(ip))
                    else:
                        for ip in network.hosts():
                            expanded.append(str(ip))
                else:
                    expanded.append(target)
            except Exception:
                # Not a valid CIDR, treat as hostname/IP
                expanded.append(target)
        
        return expanded
    
    def expand_targets_generator(self, targets: List[str]) -> Generator[str, None, None]:
        """Memory-efficient generator that yields targets one by one"""
        for target in targets:
            try:
                # Check if it's a CIDR range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    self.logger.info(f"🌐 Expanding CIDR {target} ({network.num_addresses:,} addresses)")
                    
                    for ip in network.hosts():
                        yield str(ip)
                else:
                    yield target
            except Exception as e:
                # Not a valid CIDR, treat as hostname/IP
                self.logger.debug(f"Treating {target} as hostname/IP: {e}")
                yield target
    
    def expand_targets_chunked(self, targets: List[str], chunk_size: Optional[int] = None) -> Generator[List[str], None, None]:
        """Expand targets in memory-efficient chunks"""
        if chunk_size is None:
            # Calculate total targets first to get adaptive chunk size
            total_count = self.count_total_targets(targets)
            chunk_size = self.memory_manager.get_adaptive_chunk_size(total_count)
        
        self.logger.info(f"📦 Processing targets in chunks of {chunk_size:,}")
        
        current_chunk = []
        
        for target_ip in self.expand_targets_generator(targets):
            current_chunk.append(target_ip)
            
            if len(current_chunk) >= chunk_size:
                yield current_chunk
                current_chunk = []
                
                # Check memory usage and force cleanup if needed
                usage, warning = self.memory_manager.check_memory_usage()
                if warning:
                    self.memory_manager.force_cleanup()
        
        # Yield remaining targets
        if current_chunk:
            yield current_chunk
    
    def count_total_targets(self, targets: List[str]) -> int:
        """Count total number of targets that would be expanded"""
        total = 0
        
        for target in targets:
            try:
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    total += network.num_addresses
                else:
                    total += 1
            except Exception:
                total += 1
        
        return total
    
    def estimate_memory_usage(self, targets: List[str]) -> Tuple[int, float]:
        """Estimate memory usage for target expansion"""
        total_targets = self.count_total_targets(targets)
        # Estimate ~1KB per target for IP string + processing overhead
        estimated_mb = (total_targets * 1024) / (1024 * 1024)
        
        return total_targets, estimated_mb