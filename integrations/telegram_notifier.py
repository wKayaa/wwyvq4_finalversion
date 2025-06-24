#!/usr/bin/env python3
"""
📱 Telegram Notifier
Send notifications to Telegram

Author: wKayaa
Date: 2025-01-28
"""

import aiohttp
from typing import Optional


class TelegramNotifier:
    """Telegram notification service"""
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}"
    
    async def initialize(self):
        """Initialize Telegram connection"""
        # Test connection
        try:
            await self.send_message("🚀 F8S Framework connected to Telegram")
        except Exception as e:
            print(f"⚠️ Telegram initialization failed: {str(e)}")
    
    async def send_message(self, message: str) -> bool:
        """Send message to Telegram"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/sendMessage"
                data = {
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "HTML"
                }
                
                async with session.post(url, data=data) as response:
                    return response.status == 200
        except Exception:
            return False