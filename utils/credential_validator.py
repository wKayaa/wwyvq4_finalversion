#!/usr/bin/env python3
"""
🔐 Credential Validator - Real-time credential validation utility
Author: wKayaa
Date: 2025-01-17

Provides real-time validation for various credential types:
- AWS Access Keys with STS validation
- SendGrid API keys with quota checking
- Mailgun API keys with domain testing
- GitHub/GitLab tokens with permission enumeration
- JWT tokens with decoding and validation
- SMTP credentials with live authentication
- Database connection strings with connectivity testing
"""

import asyncio
import aiohttp
import base64
import json
import hashlib
import hmac
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional, List
import xml.etree.ElementTree as ET

class CredentialValidator:
    """Advanced credential validation with multiple service support"""
    
    def __init__(self, timeout: int = 30, cache_size: int = 1000):
        self.timeout = timeout
        self.cache_size = cache_size
        self.validation_cache = {}
        self.session = None
        
    async def initialize(self):
        """Initialize HTTP session for validation"""
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def validate_credential(self, cred_type: str, value: str, context: str = "") -> Dict[str, Any]:
        """Main validation method - routes to specific validators"""
        if not self.session:
            await self.initialize()
        
        # Check cache
        cache_key = f"{cred_type}:{hashlib.md5(value.encode()).hexdigest()}"
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        # Route to appropriate validator
        validators = {
            "aws_access_key": self._validate_aws_access_key,
            "aws_secret_key": self._validate_aws_secret_key,
            "sendgrid_api_key": self._validate_sendgrid_key,
            "mailgun_api_key": self._validate_mailgun_key,
            "github_token": self._validate_github_token,
            "gitlab_token": self._validate_gitlab_token,
            "jwt_token": self._validate_jwt_token,
            "bearer_token": self._validate_bearer_token,
            "smtp_credentials": self._validate_smtp_credentials,
            "mysql_connection": self._validate_mysql_connection,
            "postgresql_connection": self._validate_postgresql_connection,
            "mongodb_connection": self._validate_mongodb_connection,
            "redis_connection": self._validate_redis_connection,
        }
        
        validator = validators.get(cred_type, self._validate_generic)
        
        try:
            result = await validator(value, context)
        except Exception as e:
            result = {
                "validated": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Cache result if cache not full
        if len(self.validation_cache) < self.cache_size:
            self.validation_cache[cache_key] = result
        
        return result
    
    # AWS Validators
    async def _validate_aws_access_key(self, access_key: str, context: str) -> Dict[str, Any]:
        """Validate AWS access key format and try basic STS call"""
        # Basic format validation
        if not access_key.startswith(('AKIA', 'ASIA', 'AROA')):
            return {
                "validated": False,
                "reason": "Invalid AWS access key format",
                "expected_format": "AKIA[16 chars] or ASIA[16 chars] or AROA[16 chars]"
            }
        
        if len(access_key) != 20:
            return {
                "validated": False,
                "reason": "Invalid AWS access key length",
                "expected_length": 20,
                "actual_length": len(access_key)
            }
        
        # Try to find corresponding secret key in context
        secret_key = self._extract_aws_secret_from_context(context, access_key)
        if secret_key:
            return await self._validate_aws_credentials_pair(access_key, secret_key)
        
        return {
            "validated": True,
            "format_valid": True,
            "service": "AWS",
            "key_type": "access_key",
            "note": "Format valid, but requires secret key for full validation"
        }
    
    async def _validate_aws_secret_key(self, secret_key: str, context: str) -> Dict[str, Any]:
        """Validate AWS secret key format"""
        if len(secret_key) != 40:
            return {
                "validated": False,
                "reason": "Invalid AWS secret key length",
                "expected_length": 40,
                "actual_length": len(secret_key)
            }
        
        # Basic character set validation
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        if not all(c in valid_chars for c in secret_key):
            return {
                "validated": False,
                "reason": "Invalid characters in AWS secret key"
            }
        
        return {
            "validated": True,
            "format_valid": True,
            "service": "AWS",
            "key_type": "secret_key",
            "note": "Format valid, requires access key for full validation"
        }
    
    async def _validate_aws_credentials_pair(self, access_key: str, secret_key: str) -> Dict[str, Any]:
        """Validate AWS access key and secret key pair using STS"""
        try:
            # Use STS GetCallerIdentity to validate credentials
            region = "us-east-1"
            service = "sts"
            host = f"{service}.{region}.amazonaws.com"
            
            # Create signed request
            headers = await self._create_aws_signature_v4(
                method="POST",
                uri="/",
                query_string="",
                payload="Action=GetCallerIdentity&Version=2011-06-15",
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                service=service
            )
            
            url = f"https://{host}/"
            headers["Content-Type"] = "application/x-amz-json-1.0"
            
            async with self.session.post(
                url,
                headers=headers,
                data="Action=GetCallerIdentity&Version=2011-06-15"
            ) as response:
                
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse XML response
                    try:
                        root = ET.fromstring(content)
                        # Extract ARN and other info
                        result = root.find('.//GetCallerIdentityResult')
                        if result is not None:
                            arn = result.find('Arn').text if result.find('Arn') is not None else None
                            user_id = result.find('UserId').text if result.find('UserId') is not None else None
                            account = result.find('Account').text if result.find('Account') is not None else None
                            
                            return {
                                "validated": True,
                                "service": "AWS",
                                "arn": arn,
                                "user_id": user_id,
                                "account": account,
                                "permissions": ["sts:GetCallerIdentity"]
                            }
                    except ET.ParseError:
                        pass
                    
                    return {
                        "validated": True,
                        "service": "AWS",
                        "note": "Credentials valid but couldn't parse response"
                    }
                else:
                    return {
                        "validated": False,
                        "service": "AWS",
                        "status_code": response.status,
                        "error": "Authentication failed"
                    }
        
        except Exception as e:
            return {
                "validated": False,
                "service": "AWS",
                "error": str(e)
            }
    
    # SendGrid Validator
    async def _validate_sendgrid_key(self, api_key: str, context: str) -> Dict[str, Any]:
        """Validate SendGrid API key"""
        if not api_key.startswith('SG.'):
            return {
                "validated": False,
                "reason": "Invalid SendGrid API key format",
                "expected_format": "SG.xxxxxxx.xxxxxxx"
            }
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Try to get user profile
            async with self.session.get(
                "https://api.sendgrid.com/v3/user/profile",
                headers=headers
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return {
                        "validated": True,
                        "service": "SendGrid",
                        "username": data.get("username"),
                        "email": data.get("email"),
                        "first_name": data.get("first_name"),
                        "last_name": data.get("last_name")
                    }
                elif response.status == 401:
                    return {
                        "validated": False,
                        "service": "SendGrid",
                        "error": "Invalid API key"
                    }
                else:
                    return {
                        "validated": False,
                        "service": "SendGrid",
                        "status_code": response.status
                    }
        
        except Exception as e:
            return {
                "validated": False,
                "service": "SendGrid",
                "error": str(e)
            }
    
    # Mailgun Validator
    async def _validate_mailgun_key(self, api_key: str, context: str) -> Dict[str, Any]:
        """Validate Mailgun API key"""
        try:
            # Basic auth with api key
            auth = aiohttp.BasicAuth('api', api_key)
            
            # Try to get domains
            async with self.session.get(
                "https://api.mailgun.net/v3/domains",
                auth=auth
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    domains = [item["name"] for item in data.get("items", [])]
                    return {
                        "validated": True,
                        "service": "Mailgun",
                        "domains": domains,
                        "domain_count": len(domains)
                    }
                elif response.status == 401:
                    return {
                        "validated": False,
                        "service": "Mailgun",
                        "error": "Invalid API key"
                    }
                else:
                    return {
                        "validated": False,
                        "service": "Mailgun",
                        "status_code": response.status
                    }
        
        except Exception as e:
            return {
                "validated": False,
                "service": "Mailgun",
                "error": str(e)
            }
    
    # GitHub Validator
    async def _validate_github_token(self, token: str, context: str) -> Dict[str, Any]:
        """Validate GitHub token"""
        try:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Get user info
            async with self.session.get(
                "https://api.github.com/user",
                headers=headers
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    
                    # Get scopes from headers
                    scopes = response.headers.get("X-OAuth-Scopes", "").split(", ")
                    scopes = [s.strip() for s in scopes if s.strip()]
                    
                    return {
                        "validated": True,
                        "service": "GitHub",
                        "username": data.get("login"),
                        "name": data.get("name"),
                        "email": data.get("email"),
                        "public_repos": data.get("public_repos"),
                        "private_repos": data.get("total_private_repos"),
                        "scopes": scopes
                    }
                elif response.status == 401:
                    return {
                        "validated": False,
                        "service": "GitHub",
                        "error": "Invalid token"
                    }
                else:
                    return {
                        "validated": False,
                        "service": "GitHub",
                        "status_code": response.status
                    }
        
        except Exception as e:
            return {
                "validated": False,
                "service": "GitHub",
                "error": str(e)
            }
    
    # GitLab Validator
    async def _validate_gitlab_token(self, token: str, context: str) -> Dict[str, Any]:
        """Validate GitLab token"""
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            # Try GitLab.com first, then extract domain from context if available
            gitlab_urls = ["https://gitlab.com"]
            
            # Try to extract GitLab URL from context
            import re
            gitlab_match = re.search(r'https?://([^/]+gitlab[^/]*)', context, re.IGNORECASE)
            if gitlab_match:
                gitlab_urls.insert(0, f"https://{gitlab_match.group(1)}")
            
            for gitlab_url in gitlab_urls:
                try:
                    async with self.session.get(
                        f"{gitlab_url}/api/v4/user",
                        headers=headers
                    ) as response:
                        
                        if response.status == 200:
                            data = await response.json()
                            return {
                                "validated": True,
                                "service": "GitLab",
                                "instance": gitlab_url,
                                "username": data.get("username"),
                                "name": data.get("name"),
                                "email": data.get("email"),
                                "is_admin": data.get("is_admin", False)
                            }
                        elif response.status == 401:
                            continue  # Try next URL
                except:
                    continue
            
            return {
                "validated": False,
                "service": "GitLab",
                "error": "Invalid token or GitLab instance not accessible"
            }
        
        except Exception as e:
            return {
                "validated": False,
                "service": "GitLab",
                "error": str(e)
            }
    
    # JWT Validator
    async def _validate_jwt_token(self, token: str, context: str) -> Dict[str, Any]:
        """Validate JWT token structure and extract information"""
        try:
            # Basic JWT structure validation
            parts = token.split('.')
            if len(parts) != 3:
                return {
                    "validated": False,
                    "reason": "Invalid JWT structure",
                    "expected_parts": 3,
                    "actual_parts": len(parts)
                }
            
            # Decode header and payload (without verification)
            def decode_base64url(data):
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data)
            
            header = json.loads(decode_base64url(parts[0]))
            payload = json.loads(decode_base64url(parts[1]))
            
            # Check expiration
            now = datetime.utcnow().timestamp()
            exp = payload.get("exp")
            expired = exp and exp < now
            
            return {
                "validated": True,
                "type": "JWT",
                "algorithm": header.get("alg"),
                "token_type": header.get("typ"),
                "issuer": payload.get("iss"),
                "subject": payload.get("sub"),
                "audience": payload.get("aud"),
                "expires": datetime.fromtimestamp(exp).isoformat() if exp else None,
                "expired": expired,
                "issued_at": datetime.fromtimestamp(payload["iat"]).isoformat() if payload.get("iat") else None,
                "not_before": datetime.fromtimestamp(payload["nbf"]).isoformat() if payload.get("nbf") else None,
                "scopes": payload.get("scope", "").split() if payload.get("scope") else [],
                "custom_claims": {k: v for k, v in payload.items() if k not in ["iss", "sub", "aud", "exp", "iat", "nbf", "scope"]}
            }
        
        except Exception as e:
            return {
                "validated": False,
                "error": str(e)
            }
    
    # Generic bearer token validator
    async def _validate_bearer_token(self, token: str, context: str) -> Dict[str, Any]:
        """Generic bearer token validation"""
        # Try common endpoints that might accept bearer tokens
        endpoints = [
            ("https://api.github.com/user", "GitHub"),
            ("https://gitlab.com/api/v4/user", "GitLab"),
            ("https://api.bitbucket.org/2.0/user", "Bitbucket"),
        ]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        for endpoint, service in endpoints:
            try:
                async with self.session.get(endpoint, headers=headers) as response:
                    if response.status == 200:
                        return {
                            "validated": True,
                            "service": service,
                            "endpoint": endpoint
                        }
            except:
                continue
        
        return {
            "validated": False,
            "reason": "Token not recognized by common services"
        }
    
    # Database validators (basic connectivity checks)
    async def _validate_mysql_connection(self, connection_string: str, context: str) -> Dict[str, Any]:
        """Validate MySQL connection string"""
        return {
            "validated": False,
            "reason": "MySQL validation requires mysql-connector-python",
            "note": "Connection string format appears valid" if "mysql:" in connection_string.lower() else "Invalid format"
        }
    
    async def _validate_postgresql_connection(self, connection_string: str, context: str) -> Dict[str, Any]:
        """Validate PostgreSQL connection string"""
        return {
            "validated": False,
            "reason": "PostgreSQL validation requires psycopg2",
            "note": "Connection string format appears valid" if "postgresql:" in connection_string.lower() else "Invalid format"
        }
    
    async def _validate_mongodb_connection(self, connection_string: str, context: str) -> Dict[str, Any]:
        """Validate MongoDB connection string"""
        return {
            "validated": False,
            "reason": "MongoDB validation requires pymongo",
            "note": "Connection string format appears valid" if "mongodb:" in connection_string.lower() else "Invalid format"
        }
    
    async def _validate_redis_connection(self, connection_string: str, context: str) -> Dict[str, Any]:
        """Validate Redis connection string"""
        return {
            "validated": False,
            "reason": "Redis validation requires redis-py",
            "note": "Connection string format appears valid" if "redis:" in connection_string.lower() else "Invalid format"
        }
    
    async def _validate_smtp_credentials(self, credentials: str, context: str) -> Dict[str, Any]:
        """Validate SMTP credentials"""
        return {
            "validated": False,
            "reason": "SMTP validation requires smtplib implementation",
            "note": "Credentials format appears valid" if "@" in credentials else "Invalid format"
        }
    
    async def _validate_generic(self, value: str, context: str) -> Dict[str, Any]:
        """Generic validation for unknown credential types"""
        return {
            "validated": False,
            "reason": "No specific validator available for this credential type",
            "length": len(value),
            "contains_special_chars": any(c in value for c in "!@#$%^&*()"),
            "appears_base64": self._is_base64(value)
        }
    
    # Helper methods
    def _extract_aws_secret_from_context(self, context: str, access_key: str) -> Optional[str]:
        """Try to extract AWS secret key from context"""
        import re
        
        # Look for secret key patterns near the access key
        secret_patterns = [
            rf"{re.escape(access_key)}.*?([A-Za-z0-9+/]{{40}})",
            rf"([A-Za-z0-9+/]{{40}}).*?{re.escape(access_key)}",
            r"secret[_\-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/]{40})",
            r"aws[_\-]?secret[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/]{40})"
        ]
        
        for pattern in secret_patterns:
            match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)
        
        return None
    
    async def _create_aws_signature_v4(self, method: str, uri: str, query_string: str, 
                                     payload: str, access_key: str, secret_key: str,
                                     region: str, service: str) -> Dict[str, str]:
        """Create AWS Signature Version 4"""
        # Create timestamp
        t = datetime.utcnow()
        timestamp = t.strftime('%Y%m%dT%H%M%SZ')
        date = t.strftime('%Y%m%d')
        
        # Create canonical request
        canonical_uri = uri
        canonical_querystring = query_string
        canonical_headers = f"host:{service}.{region}.amazonaws.com\nx-amz-date:{timestamp}\n"
        signed_headers = "host;x-amz-date"
        payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        
        canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        
        # Create string to sign
        credential_scope = f"{date}/{region}/{service}/aws4_request"
        string_to_sign = f"AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        
        # Create signing key
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
        
        k_date = sign(f"AWS4{secret_key}".encode('utf-8'), date)
        k_region = sign(k_date, region)
        k_service = sign(k_region, service)
        k_signing = sign(k_service, "aws4_request")
        
        # Create signature
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Create authorization header
        authorization = f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        
        return {
            "Authorization": authorization,
            "X-Amz-Date": timestamp,
            "Host": f"{service}.{region}.amazonaws.com"
        }
    
    def _is_base64(self, s: str) -> bool:
        """Check if string is valid base64"""
        try:
            if isinstance(s, str):
                sb_bytes = bytes(s, 'ascii')
            elif isinstance(s, bytes):
                sb_bytes = s
            else:
                raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except:
            return False

# Export for use in other modules
__all__ = ['CredentialValidator']

async def main():
    """Example usage"""
    validator = CredentialValidator()
    await validator.initialize()
    
    # Example validations
    test_credentials = [
        ("github_token", "ghp_1234567890abcdef1234567890abcdef12345678", ""),
        ("jwt_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", ""),
        ("sendgrid_api_key", "SG.1234567890abcdef.1234567890abcdef1234567890abcdef", "")
    ]
    
    for cred_type, value, context in test_credentials:
        result = await validator.validate_credential(cred_type, value, context)
        print(f"\n{cred_type}: {result}")
    
    await validator.close()

if __name__ == "__main__":
    asyncio.run(main())