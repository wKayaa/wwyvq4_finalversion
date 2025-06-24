#!/usr/bin/env python3
"""
🔑 Credential Extractor - Phase 3
Advanced credential extraction with pattern matching and validation

Author: wKayaa
Date: 2025-01-28
"""

import re
import base64
import json
from typing import Dict, List, Optional


class CredentialExtractor:
    """Extract credentials from exploited clusters with advanced pattern matching"""
    
    def __init__(self, error_handler=None):
        self.error_handler = error_handler
        
        # Credential patterns based on real-world findings
        self.credential_patterns = {
            "aws_access_key": [
                r'AKIA[0-9A-Z]{16}',
                r'ASIA[0-9A-Z]{16}',
                r'AROA[0-9A-Z]{16}'
            ],
            "aws_secret_key": [
                r'[A-Za-z0-9+/]{40}',
                r'[A-Za-z0-9+/]{40}='
            ],
            "aws_session_token": [
                r'[A-Za-z0-9+/]{100,}={0,2}'
            ],
            "gcp_service_account": [
                r'\{[^}]*"type":\s*"service_account"[^}]*\}',
                r'-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----'
            ],
            "azure_client_secret": [
                r'[A-Za-z0-9~._-]{34}',
                r'[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}'
            ],
            "jwt_token": [
                r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                r'Bearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            ],
            "k8s_service_token": [
                r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            ],
            "sendgrid_api_key": [
                r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                r'SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            ],
            "github_token": [
                r'ghp_[A-Za-z0-9]{36}',
                r'gho_[A-Za-z0-9]{36}',
                r'ghu_[A-Za-z0-9]{36}',
                r'ghs_[A-Za-z0-9]{36}',
                r'ghr_[A-Za-z0-9]{36}'
            ],
            "docker_auth": [
                r'\{[^}]*"auths"[^}]*\}',
                r'"auth":\s*"[A-Za-z0-9+/]+=*"'
            ],
            "slack_token": [
                r'xox[baprs]-[A-Za-z0-9-]+',
                r'https://hooks\.slack\.com/services/[A-Z0-9/]+'
            ],
            "database_url": [
                r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+',
                r'postgresql://[^\s]+',
                r'mysql://[^\s]+',
                r'mongodb://[^\s]+'
            ],
            "ssh_private_key": [
                r'-----BEGIN[A-Z ]+PRIVATE KEY-----[^-]+-----END[A-Z ]+PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----[^-]+-----END OPENSSH PRIVATE KEY-----'
            ],
            "x509_certificate": [
                r'-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----'
            ]
        }
        
        # High-confidence patterns (less false positives)
        self.high_confidence_patterns = {
            "aws_access_key": r'AKIA[0-9A-Z]{16}',
            "sendgrid_api_key": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            "github_token": r'gh[pso]_[A-Za-z0-9]{36}',
            "jwt_token": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        }
        
        # Context patterns to improve accuracy
        self.context_patterns = {
            "aws": [
                "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN",
                "access_key_id", "secret_access_key", "session_token"
            ],
            "gcp": [
                "GOOGLE_APPLICATION_CREDENTIALS", "service_account_key",
                "private_key_id", "client_email"
            ],
            "kubernetes": [
                "KUBECONFIG", "service-account-token", "ca.crt", "namespace"
            ]
        }
    
    async def extract_credentials(self, exploitation_result: Dict) -> List[Dict]:
        """Extract credentials from exploitation results"""
        all_credentials = []
        
        # Extract from secrets found during exploitation
        secrets = exploitation_result.get("secrets_found", [])
        for secret in secrets:
            credentials = await self._process_secret(secret, exploitation_result)
            all_credentials.extend(credentials)
        
        # Extract from compromised pods
        if exploitation_result.get("pods_compromised", 0) > 0:
            pod_credentials = await self._extract_from_pods(exploitation_result)
            all_credentials.extend(pod_credentials)
        
        # Extract from service account tokens
        if exploitation_result.get("exploits_used"):
            sa_credentials = await self._extract_service_account_tokens(exploitation_result)
            all_credentials.extend(sa_credentials)
        
        # Deduplicate and enrich credentials
        unique_credentials = self._deduplicate_credentials(all_credentials)
        enriched_credentials = await self._enrich_credentials(unique_credentials)
        
        return enriched_credentials
    
    async def _process_secret(self, secret: Dict, context: Dict) -> List[Dict]:
        """Process a single secret for credential extraction"""
        credentials = []
        
        secret_value = secret.get("value", "")
        secret_type = secret.get("type", "unknown")
        cluster_endpoint = context.get("cluster", {}).get("endpoint", "unknown")
        
        # Try to decode if base64 encoded
        decoded_value = self._try_decode_base64(secret_value)
        
        # Extract credentials using patterns
        for cred_type, patterns in self.credential_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, decoded_value, re.MULTILINE | re.DOTALL)
                for match in matches:
                    credential = {
                        "type": cred_type,
                        "value": match.strip(),
                        "source": f"secret_{secret_type}",
                        "cluster": cluster_endpoint,
                        "confidence": self._calculate_confidence(cred_type, match, decoded_value),
                        "context": self._extract_context(cred_type, decoded_value),
                        "timestamp": context.get("timestamp", "unknown")
                    }
                    credentials.append(credential)
        
        return credentials
    
    async def _extract_from_pods(self, exploitation_result: Dict) -> List[Dict]:
        """Extract credentials from compromised pods"""
        credentials = []
        cluster_endpoint = exploitation_result.get("cluster", {}).get("endpoint", "unknown")
        
        # Simulate pod credential extraction
        pod_locations = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/home/.aws/credentials",
            "/home/.gcp/credentials.json",
            "/etc/kubernetes/pki/",
            "/var/lib/kubelet/pki/",
            "/root/.kube/config"
        ]
        
        for location in pod_locations:
            # Simulate finding credentials in common locations
            if "kubernetes.io/serviceaccount" in location:
                credentials.append({
                    "type": "k8s_service_token",
                    "value": "eyJhbGciOiJSUzI1NiI...",  # Mock token
                    "source": f"pod_file_{location}",
                    "cluster": cluster_endpoint,
                    "confidence": 95.0,
                    "context": {"location": location, "file_type": "service_account_token"}
                })
            elif ".aws" in location:
                credentials.append({
                    "type": "aws_access_key",
                    "value": "AKIAIOSFODNN7EXAMPLE",
                    "source": f"pod_file_{location}",
                    "cluster": cluster_endpoint,
                    "confidence": 90.0,
                    "context": {"location": location, "file_type": "aws_credentials"}
                })
        
        return credentials
    
    async def _extract_service_account_tokens(self, exploitation_result: Dict) -> List[Dict]:
        """Extract service account tokens from exploitation"""
        credentials = []
        cluster_endpoint = exploitation_result.get("cluster", {}).get("endpoint", "unknown")
        
        # Extract tokens from exploitation results
        exploits_used = exploitation_result.get("exploits_used", [])
        
        if "service_account_theft" in exploits_used:
            # Mock service account token extraction
            credentials.append({
                "type": "jwt_token",
                "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "source": "service_account_theft",
                "cluster": cluster_endpoint,
                "confidence": 98.0,
                "context": {
                    "service_account": "default",
                    "namespace": "kube-system",
                    "permissions": ["get", "list", "create"]
                }
            })
        
        return credentials
    
    def _try_decode_base64(self, value: str) -> str:
        """Try to decode base64 encoded values"""
        try:
            # Try standard base64 decoding
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            return decoded
        except Exception:
            return value
    
    def _calculate_confidence(self, cred_type: str, match: str, context: str) -> float:
        """Calculate confidence score for credential match"""
        base_confidence = 70.0
        
        # High confidence patterns
        if cred_type in self.high_confidence_patterns:
            if re.match(self.high_confidence_patterns[cred_type], match):
                base_confidence = 95.0
        
        # Context-based confidence boost
        context_lower = context.lower()
        if cred_type.startswith("aws") and any(pattern in context_lower for pattern in self.context_patterns["aws"]):
            base_confidence += 15.0
        elif cred_type.startswith("gcp") and any(pattern in context_lower for pattern in self.context_patterns["gcp"]):
            base_confidence += 15.0
        elif cred_type.startswith("k8s") and any(pattern in context_lower for pattern in self.context_patterns["kubernetes"]):
            base_confidence += 15.0
        
        # Length-based confidence for certain types
        if cred_type == "aws_access_key" and len(match) == 20:
            base_confidence += 10.0
        elif cred_type == "aws_secret_key" and len(match) == 40:
            base_confidence += 10.0
        
        return min(base_confidence, 100.0)
    
    def _extract_context(self, cred_type: str, full_text: str) -> Dict:
        """Extract contextual information around credential"""
        context = {}
        
        # Look for environment variable names
        env_patterns = [
            r'([A-Z_]+)\s*=\s*["\']?[^"\']*["\']?',
            r'export\s+([A-Z_]+)=',
            r'(\w+):\s*["\']?[^"\']*["\']?'
        ]
        
        for pattern in env_patterns:
            matches = re.findall(pattern, full_text, re.IGNORECASE)
            if matches:
                context["environment_variables"] = matches[:5]  # Limit to 5
                break
        
        # Look for configuration sections
        if "aws" in cred_type.lower():
            aws_context = re.search(r'\[([^\]]+)\]', full_text)
            if aws_context:
                context["aws_profile"] = aws_context.group(1)
        
        return context
    
    def _deduplicate_credentials(self, credentials: List[Dict]) -> List[Dict]:
        """Remove duplicate credentials"""
        seen = set()
        unique_credentials = []
        
        for cred in credentials:
            # Create a unique key based on type and value
            key = f"{cred['type']}:{cred['value'][:20]}"
            if key not in seen:
                seen.add(key)
                unique_credentials.append(cred)
        
        return unique_credentials
    
    async def _enrich_credentials(self, credentials: List[Dict]) -> List[Dict]:
        """Enrich credentials with additional metadata"""
        enriched = []
        
        for cred in credentials:
            # Add risk assessment
            cred["risk_level"] = self._assess_risk_level(cred)
            
            # Add validation priority
            cred["validation_priority"] = self._calculate_validation_priority(cred)
            
            # Add recommended actions
            cred["recommended_actions"] = self._get_recommended_actions(cred)
            
            enriched.append(cred)
        
        # Sort by validation priority
        enriched.sort(key=lambda x: x["validation_priority"], reverse=True)
        
        return enriched
    
    def _assess_risk_level(self, credential: Dict) -> str:
        """Assess risk level of credential"""
        confidence = credential.get("confidence", 0)
        cred_type = credential.get("type", "")
        
        high_risk_types = ["aws_access_key", "gcp_service_account", "azure_client_secret"]
        medium_risk_types = ["jwt_token", "sendgrid_api_key", "github_token"]
        
        if confidence >= 90 and cred_type in high_risk_types:
            return "CRITICAL"
        elif confidence >= 80 and cred_type in high_risk_types:
            return "HIGH"
        elif confidence >= 70 and cred_type in medium_risk_types:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_validation_priority(self, credential: Dict) -> int:
        """Calculate validation priority (higher = more important)"""
        priority = 0
        
        # Base priority on confidence
        priority += credential.get("confidence", 0)
        
        # Type-based priority
        type_priorities = {
            "aws_access_key": 100,
            "aws_secret_key": 100,
            "gcp_service_account": 95,
            "azure_client_secret": 90,
            "jwt_token": 80,
            "sendgrid_api_key": 75,
            "github_token": 70,
            "k8s_service_token": 85
        }
        
        cred_type = credential.get("type", "")
        priority += type_priorities.get(cred_type, 50)
        
        return int(priority)
    
    def _get_recommended_actions(self, credential: Dict) -> List[str]:
        """Get recommended actions for credential"""
        cred_type = credential.get("type", "")
        risk_level = credential.get("risk_level", "LOW")
        
        actions = []
        
        if risk_level in ["CRITICAL", "HIGH"]:
            actions.append("Validate immediately")
            actions.append("Rotate credential if valid")
        
        if cred_type.startswith("aws"):
            actions.extend([
                "Check AWS account permissions",
                "Review CloudTrail logs",
                "Check for unauthorized resources"
            ])
        elif cred_type.startswith("gcp"):
            actions.extend([
                "Check GCP project permissions",
                "Review audit logs",
                "Verify service account usage"
            ])
        elif cred_type == "jwt_token":
            actions.extend([
                "Decode JWT payload",
                "Check token expiration",
                "Verify token permissions"
            ])
        
        return actions