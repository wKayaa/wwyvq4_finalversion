#!/usr/bin/env python3
"""
🎵 Discord Notifier
Send notifications to Discord

Author: wKayaa
Date: 2025-01-28
"""

import aiohttp
from typing import Optional


class DiscordNotifier:
    """Discord notification service"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def send_message(self, message: str) -> bool:
        """Send message to Discord"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "content": message
                }
                
                async with session.post(self.webhook_url, json=data) as response:
                    return response.status == 204
        except Exception:
            return False