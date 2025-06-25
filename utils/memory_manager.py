#!/usr/bin/env python3
"""
🧠 Memory Manager
Intelligent memory management for large-scale scanning operations

Author: wKayaa
Date: 2025-01-28
"""

import psutil
import gc
import logging
from typing import Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class MemoryConfig:
    """Memory configuration for adaptive processing"""
    total_memory_gb: float
    available_memory_gb: float
    recommended_chunk_size: int
    max_concurrent_tasks: int
    memory_threshold_percent: float = 80.0


class MemoryManager:
    """Intelligent memory management for large-scale operations"""
    
    def __init__(self, safety_margin_percent: float = 20.0):
        self.safety_margin = safety_margin_percent / 100.0
        self.logger = logging.getLogger("MemoryManager")
        
    def get_memory_info(self) -> MemoryConfig:
        """Get current memory information and recommendations"""
        memory = psutil.virtual_memory()
        
        total_gb = memory.total / (1024**3)
        available_gb = memory.available / (1024**3)
        
        # Calculate recommended chunk size based on available memory
        # Assume each IP target uses ~1KB memory on average
        # Reserve memory for processing overhead
        usable_memory_gb = available_gb * (1 - self.safety_margin)
        chunk_size = max(1000, int(usable_memory_gb * 1024 * 1024))  # Convert to number of targets
        
        # Limit chunk size to reasonable maximums
        chunk_size = min(chunk_size, 100000)  # Max 100K targets per chunk
        
        # Calculate max concurrent tasks based on memory
        max_concurrent = max(50, min(1000, int(available_gb * 100)))
        
        config = MemoryConfig(
            total_memory_gb=total_gb,
            available_memory_gb=available_gb,
            recommended_chunk_size=chunk_size,
            max_concurrent_tasks=max_concurrent
        )
        
        self.logger.info(f"💾 Memory Config: {total_gb:.1f}GB total, {available_gb:.1f}GB available")
        self.logger.info(f"📊 Recommended: {chunk_size:,} targets/chunk, {max_concurrent} concurrent tasks")
        
        return config
    
    def check_memory_usage(self) -> Tuple[float, bool]:
        """Check current memory usage and return percentage and warning flag"""
        memory = psutil.virtual_memory()
        usage_percent = memory.percent
        
        warning = usage_percent > 80.0
        if warning:
            self.logger.warning(f"⚠️ High memory usage: {usage_percent:.1f}%")
        
        return usage_percent, warning
    
    def force_cleanup(self):
        """Force garbage collection and memory cleanup"""
        self.logger.info("🧹 Forcing memory cleanup...")
        gc.collect()
        
    def get_adaptive_chunk_size(self, total_targets: int) -> int:
        """Get adaptive chunk size based on total targets and available memory"""
        config = self.get_memory_info()
        
        # If we have fewer targets than recommended chunk size, use all targets
        if total_targets <= config.recommended_chunk_size:
            return total_targets
        
        # For very large target sets, use smaller chunks to be safe
        if total_targets > 1000000:  # 1M+ targets
            return min(config.recommended_chunk_size, 50000)
        
        return config.recommended_chunk_size
    
    def monitor_memory_during_processing(self) -> Dict[str, float]:
        """Monitor memory during processing and return metrics"""
        memory = psutil.virtual_memory()
        process = psutil.Process()
        
        return {
            "system_memory_percent": memory.percent,
            "system_available_gb": memory.available / (1024**3),
            "process_memory_mb": process.memory_info().rss / (1024**2),
            "process_memory_percent": process.memory_percent()
        }