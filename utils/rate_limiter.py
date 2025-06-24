#!/usr/bin/env python3
"""
⏱️ Rate Limiter
Control concurrent operations

Author: wKayaa
Date: 2025-01-28
"""

import asyncio


class RateLimiter:
    """Rate limiter for concurrent operations"""
    
    def __init__(self, max_concurrent: int = 100):
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def __aenter__(self):
        await self.semaphore.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.semaphore.release()