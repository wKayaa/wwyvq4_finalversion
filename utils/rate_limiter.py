#!/usr/bin/env python3
"""
⏱️ Enhanced Rate Limiter for Large Scale Operations
Control concurrent operations with intelligent adaptive limiting

Author: wKayaa
Date: 2025-01-17
"""

import asyncio
import time
from typing import Dict, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    max_requests_per_second: int = 100
    max_burst: int = 200
    adaptive_mode: bool = True
    error_backoff_factor: float = 2.0
    success_speedup_factor: float = 1.1
    min_delay: float = 0.001
    max_delay: float = 5.0


class AdaptiveRateLimiter:
    """Adaptive rate limiter for large-scale operations"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_burst)
        self.request_times = deque(maxlen=config.max_requests_per_second * 2)
        self.current_delay = config.min_delay
        self.error_count = 0
        self.success_count = 0
        self.last_adjustment = time.time()
        
    async def acquire(self) -> bool:
        """Acquire permission to make a request"""
        await self.semaphore.acquire()
        
        current_time = time.time()
        
        # Remove old request times
        cutoff_time = current_time - 1.0  # 1 second window
        while self.request_times and self.request_times[0] < cutoff_time:
            self.request_times.popleft()
        
        # Check if we need to wait
        if len(self.request_times) >= self.config.max_requests_per_second:
            # Wait until we can make another request
            wait_time = 1.0 - (current_time - self.request_times[0])
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        # Apply adaptive delay if enabled
        if self.config.adaptive_mode and self.current_delay > self.config.min_delay:
            await asyncio.sleep(self.current_delay)
        
        # Record this request
        self.request_times.append(time.time())
        return True
    
    def release(self, success: bool = True):
        """Release the semaphore and update adaptive parameters"""
        self.semaphore.release()
        
        if not self.config.adaptive_mode:
            return
        
        current_time = time.time()
        
        # Update success/error counts
        if success:
            self.success_count += 1
            self.error_count = max(0, self.error_count - 1)  # Reduce error count on success
        else:
            self.error_count += 1
            self.success_count = max(0, self.success_count - 1)  # Reduce success count on error
        
        # Adjust delay based on error rate (every 10 requests or 5 seconds)
        if (self.success_count + self.error_count) % 10 == 0 or (current_time - self.last_adjustment) > 5.0:
            self._adjust_delay()
            self.last_adjustment = current_time
    
    def _adjust_delay(self):
        """Adjust delay based on recent performance"""
        total_requests = self.success_count + self.error_count
        if total_requests == 0:
            return
        
        error_rate = self.error_count / total_requests
        
        if error_rate > 0.1:  # More than 10% errors
            # Slow down
            self.current_delay = min(
                self.current_delay * self.config.error_backoff_factor,
                self.config.max_delay
            )
        elif error_rate < 0.02:  # Less than 2% errors
            # Speed up
            self.current_delay = max(
                self.current_delay / self.config.success_speedup_factor,
                self.config.min_delay
            )
    
    def get_stats(self) -> Dict:
        """Get current rate limiter statistics"""
        total_requests = self.success_count + self.error_count
        error_rate = (self.error_count / total_requests) if total_requests > 0 else 0
        
        return {
            "current_delay": self.current_delay,
            "error_rate": error_rate,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "requests_in_window": len(self.request_times),
            "available_permits": self.semaphore._value
        }

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        success = exc_type is None
        self.release(success)


class RateLimiter:
    """Simple rate limiter for backward compatibility"""
    
    def __init__(self, max_concurrent: int = 100):
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def __aenter__(self):
        await self.semaphore.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.semaphore.release()


class TokenBucket:
    """Token bucket implementation for precise rate limiting"""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Consume tokens from the bucket"""
        async with self._lock:
            now = time.time()
            
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    async def wait_for_tokens(self, tokens: int = 1):
        """Wait until tokens are available"""
        while not await self.consume(tokens):
            # Calculate wait time
            needed_tokens = tokens - self.tokens
            wait_time = needed_tokens / self.rate
            await asyncio.sleep(min(wait_time, 0.1))  # Don't wait more than 100ms at a time