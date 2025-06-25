#!/usr/bin/env python3
"""
🔍 High-Performance IP Scanner
Advanced IP range scanning with CIDR support and AWS service detection

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import aiohttp
import ipaddress
import socket
import time
from typing import List, Dict, Optional, Iterator, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging
import random

@dataclass
class ScanResult:
    """Individual scan result"""
    ip: str
    port: int
    status: str  # open, closed, filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time: Optional[float] = None
    headers: Optional[Dict] = None

@dataclass
class PortScanConfig:
    """Port scanning configuration"""
    common_ports: List[int]
    aws_ports: List[int]
    timeout: float
    max_concurrent: int
    stealth_mode: bool

class IPScanner:
    """High-performance IP scanner with AWS service detection"""
    
    def __init__(self, max_concurrent: int = 1000, timeout: float = 3.0, stealth_mode: bool = True):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.stealth_mode = stealth_mode
        
        # Port configurations
        self.port_config = PortScanConfig(
            common_ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
            aws_ports=[
                # EC2/IMDS
                80, 443, 
                # Kubernetes/EKS
                6443, 8443, 10250, 10251, 10252, 8080, 8001, 8888,
                # Database ports
                3306, 5432, 1433, 1521, 27017, 6379,
                # Other AWS services
                9200, 9300,  # Elasticsearch
                5601,       # Kibana
                9000,       # MinIO/S3-compatible
                8086,       # InfluxDB
                9092,       # Kafka
                2181,       # Zookeeper
                2379, 2380, # etcd
                8500,       # Consul
                4040,       # Spark
                8888,       # Jupyter
                3000,       # Grafana
                9090,       # Prometheus
                8080, 8081, 8082, 8083, 8084, 8085  # Various web services
            ],
            timeout=timeout,
            max_concurrent=max_concurrent,
            stealth_mode=stealth_mode
        )
        
        # AWS service detection patterns
        self.aws_service_patterns = {
            "ec2_imds": {
                "ports": [80, 443],
                "paths": ["/latest/meta-data/", "/latest/meta-data/iam/"],
                "indicators": ["ami-id", "instance-id", "security-credentials"]
            },
            "eks": {
                "ports": [6443, 8443, 443],
                "paths": ["/api/v1", "/healthz", "/version"],
                "indicators": ["kubernetes", "k8s", "apiVersion"]
            },
            "s3": {
                "ports": [80, 443, 9000],
                "paths": ["/", "/.well-known/"],
                "indicators": ["ListBucketResult", "AmazonS3", "s3.amazonaws.com"]
            },
            "elasticsearch": {
                "ports": [9200, 9300],
                "paths": ["/", "/_cluster/health"],
                "indicators": ["elasticsearch", "cluster_name", "version"]
            },
            "kubernetes_api": {
                "ports": [6443, 8443, 8001, 8080],
                "paths": ["/api/v1", "/apis", "/healthz"],
                "indicators": ["apiVersion", "kind", "kubernetes"]
            },
            "kubelet": {
                "ports": [10250, 10255],
                "paths": ["/stats/summary", "/pods", "/healthz"],
                "indicators": ["kubelet", "containers", "pods"]
            },
            "etcd": {
                "ports": [2379, 2380],
                "paths": ["/version", "/health"],
                "indicators": ["etcd", "cluster"]
            },
            "docker_api": {
                "ports": [2375, 2376],
                "paths": ["/version", "/containers/json"],
                "indicators": ["Docker", "ApiVersion"]
            }
        }
        
        # User agents for stealth scanning
        self.user_agents = [
            "Mozilla/5.0 (compatible; AWS-CLI/2.0)",
            "Amazon CloudWatch Agent",
            "aws-sdk-python/1.26.0",
            "kubectl/v1.28.0",
            "Mozilla/5.0 (compatible; Kubernetes-Health-Check/1.0)",
            "Python-urllib/3.9",
            "curl/7.68.0"
        ]
        
        self.logger = logging.getLogger("IPScanner")
        self.scan_stats = {
            "total_ips": 0,
            "scanned_ips": 0,
            "open_ports": 0,
            "identified_services": 0,
            "scan_start_time": None,
            "scan_end_time": None
        }
        
    async def scan_range(self, target_range: str, scan_type: str = "aws_focused") -> List[Dict]:
        """Scan IP range with service detection"""
        self.scan_stats["scan_start_time"] = datetime.utcnow()
        
        # Expand target range
        target_ips = self._expand_target_range(target_range)
        self.scan_stats["total_ips"] = len(target_ips)
        
        self.logger.info(f"🎯 Scanning {len(target_ips)} IPs in range {target_range}")
        
        # Determine ports to scan based on scan type
        if scan_type == "aws_focused":
            ports_to_scan = self.port_config.aws_ports
        elif scan_type == "common":
            ports_to_scan = self.port_config.common_ports
        elif scan_type == "comprehensive":
            ports_to_scan = list(set(self.port_config.common_ports + self.port_config.aws_ports))
        else:
            ports_to_scan = self.port_config.aws_ports
            
        # Perform scanning
        scan_results = await self._perform_parallel_scan(target_ips, ports_to_scan)
        
        # Group results by IP and perform service detection
        grouped_results = self._group_results_by_ip(scan_results)
        enhanced_results = await self._enhance_with_service_detection(grouped_results)
        
        self.scan_stats["scan_end_time"] = datetime.utcnow()
        
        return enhanced_results
        
    def _expand_target_range(self, target_range: str) -> List[str]:
        """Expand CIDR range or domain to individual IPs"""
        ips = []
        
        try:
            # Handle CIDR notation
            if '/' in target_range:
                network = ipaddress.IPv4Network(target_range, strict=False)
                # Limit expansion for performance (max 10000 IPs)
                ip_list = list(network.hosts())
                if len(ip_list) > 10000:
                    self.logger.warning(f"Large range detected ({len(ip_list)} IPs), limiting to first 10000")
                    ip_list = ip_list[:10000]
                ips = [str(ip) for ip in ip_list]
            else:
                # Single IP or hostname
                try:
                    # Try to resolve hostname
                    resolved_ip = socket.gethostbyname(target_range)
                    ips = [resolved_ip]
                except socket.gaierror:
                    # Assume it's already an IP
                    ips = [target_range]
                    
        except Exception as e:
            self.logger.error(f"Error expanding target range {target_range}: {str(e)}")
            
        return ips
        
    async def _perform_parallel_scan(self, ips: List[str], ports: List[int]) -> List[ScanResult]:
        """Perform parallel port scanning"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []
        
        async def scan_ip_port(ip: str, port: int) -> Optional[ScanResult]:
            async with semaphore:
                if self.stealth_mode:
                    # Add random delay for stealth
                    await asyncio.sleep(random.uniform(0.01, 0.1))
                return await self._scan_single_port(ip, port)
        
        # Create tasks for all IP:port combinations
        tasks = []
        for ip in ips:
            for port in ports:
                tasks.append(scan_ip_port(ip, port))
        
        # Execute with progress tracking
        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, ScanResult) and result.status == "open":
                    results.append(result)
                    self.scan_stats["open_ports"] += 1
            
            self.scan_stats["scanned_ips"] = min(len(ips), (i + batch_size) // len(ports))
            
            # Progress update
            if i % (batch_size * 5) == 0:
                progress = (i / len(tasks)) * 100
                self.logger.info(f"📊 Scan progress: {progress:.1f}% ({self.scan_stats['open_ports']} open ports found)")
                
        return results
        
    async def _scan_single_port(self, ip: str, port: int) -> Optional[ScanResult]:
        """Scan single IP:port combination"""
        start_time = time.time()
        
        try:
            # TCP connection test
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            response_time = time.time() - start_time
            
            # Try to get banner
            banner = None
            try:
                writer.write(b'\r\n')
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
                
            return ScanResult(
                ip=ip,
                port=port,
                status="open",
                banner=banner,
                response_time=response_time
            )
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            self.logger.debug(f"Error scanning {ip}:{port}: {str(e)}")
            return None
            
    def _group_results_by_ip(self, scan_results: List[ScanResult]) -> Dict[str, List[ScanResult]]:
        """Group scan results by IP address"""
        grouped = {}
        for result in scan_results:
            if result.ip not in grouped:
                grouped[result.ip] = []
            grouped[result.ip].append(result)
        return grouped
        
    async def _enhance_with_service_detection(self, grouped_results: Dict[str, List[ScanResult]]) -> List[Dict]:
        """Enhance results with AWS service detection"""
        enhanced_results = []
        
        for ip, port_results in grouped_results.items():
            ip_result = {
                "ip": ip,
                "open_ports": [r.port for r in port_results],
                "services": [],
                "potential_aws_services": [],
                "scan_details": {
                    "ports_scanned": len(port_results),
                    "response_times": [r.response_time for r in port_results if r.response_time],
                    "banners": [{"port": r.port, "banner": r.banner} for r in port_results if r.banner]
                }
            }
            
            # Perform service detection for each open port
            for port_result in port_results:
                service_info = await self._detect_service(ip, port_result.port, port_result.banner)
                if service_info:
                    ip_result["services"].append(service_info)
                    if service_info.get("aws_related"):
                        ip_result["potential_aws_services"].append(service_info)
                        self.scan_stats["identified_services"] += 1
                        
            enhanced_results.append(ip_result)
            
        return enhanced_results
        
    async def _detect_service(self, ip: str, port: int, banner: Optional[str]) -> Optional[Dict]:
        """Detect specific service on IP:port"""
        # Check each AWS service pattern
        for service_name, service_config in self.aws_service_patterns.items():
            if port in service_config["ports"]:
                # Try HTTP detection first
                service_info = await self._detect_http_service(ip, port, service_name, service_config)
                if service_info:
                    return service_info
                    
                # Fallback to banner analysis
                if banner:
                    for indicator in service_config["indicators"]:
                        if indicator.lower() in banner.lower():
                            return {
                                "service": service_name,
                                "port": port,
                                "detection_method": "banner",
                                "confidence": 0.7,
                                "aws_related": self._is_aws_related(service_name),
                                "details": {"banner": banner}
                            }
                            
        return None
        
    async def _detect_http_service(self, ip: str, port: int, service_name: str, service_config: Dict) -> Optional[Dict]:
        """Detect HTTP-based service"""
        for protocol in ["https", "http"]:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    headers = {"User-Agent": random.choice(self.user_agents)}
                    
                    for path in service_config["paths"]:
                        url = f"{protocol}://{ip}:{port}{path}"
                        
                        try:
                            async with session.get(url, headers=headers) as response:
                                if response.status in [200, 401, 403]:
                                    content = await response.text()
                                    
                                    # Check for service indicators
                                    for indicator in service_config["indicators"]:
                                        if indicator.lower() in content.lower():
                                            return {
                                                "service": service_name,
                                                "port": port,
                                                "protocol": protocol,
                                                "path": path,
                                                "detection_method": "http_content",
                                                "confidence": 0.9,
                                                "aws_related": self._is_aws_related(service_name),
                                                "details": {
                                                    "url": url,
                                                    "status_code": response.status,
                                                    "headers": dict(response.headers),
                                                    "indicator_found": indicator,
                                                    "content_preview": content[:500]
                                                }
                                            }
                        except Exception:
                            continue
                            
            except Exception:
                continue
                
        return None
        
    def _is_aws_related(self, service_name: str) -> bool:
        """Check if service is AWS-related"""
        aws_services = ["ec2_imds", "eks", "s3"]
        return service_name in aws_services
        
    async def scan_specific_ports(self, targets: List[str], ports: List[int]) -> List[Dict]:
        """Scan specific ports on given targets"""
        all_results = []
        
        for target in targets:
            target_ips = self._expand_target_range(target)
            
            for ip in target_ips:
                ip_results = []
                
                for port in ports:
                    result = await self._scan_single_port(ip, port)
                    if result and result.status == "open":
                        ip_results.append(result)
                        
                if ip_results:
                    # Group and enhance results
                    grouped = {ip: ip_results}
                    enhanced = await self._enhance_with_service_detection(grouped)
                    all_results.extend(enhanced)
                    
        return all_results
        
    async def fast_tcp_scan(self, targets: List[str], top_ports: int = 1000) -> List[Dict]:
        """Fast TCP scan of top ports"""
        # Top 1000 ports list (simplified for brevity)
        top_port_list = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
            # AWS/Cloud specific ports
            6443, 8443, 10250, 8080, 8081, 8082, 8083, 8084, 8085, 9000, 9200, 2379, 2380
        ]
        
        # Limit to requested number of top ports
        ports_to_scan = top_port_list[:min(top_ports, len(top_port_list))]
        
        return await self.scan_specific_ports(targets, ports_to_scan)
        
    def get_scan_statistics(self) -> Dict:
        """Get scanning statistics"""
        stats = self.scan_stats.copy()
        
        if stats["scan_start_time"] and stats["scan_end_time"]:
            duration = (stats["scan_end_time"] - stats["scan_start_time"]).total_seconds()
            stats["scan_duration_seconds"] = duration
            stats["ips_per_second"] = stats["scanned_ips"] / duration if duration > 0 else 0
            stats["ports_per_second"] = stats["open_ports"] / duration if duration > 0 else 0
            
        return stats
        
    async def scan_cidr_ranges(self, cidr_ranges: List[str], scan_type: str = "aws_focused") -> List[Dict]:
        """Scan multiple CIDR ranges efficiently"""
        all_results = []
        
        for cidr_range in cidr_ranges:
            self.logger.info(f"🎯 Starting scan of CIDR range: {cidr_range}")
            range_results = await self.scan_range(cidr_range, scan_type)
            all_results.extend(range_results)
            
            # Progress update
            self.logger.info(f"✅ Completed {cidr_range}: {len(range_results)} hosts with services found")
            
        return all_results
        
    def export_results(self, results: List[Dict], format: str = "json") -> str:
        """Export scan results in specified format"""
        if format == "json":
            import json
            return json.dumps(results, indent=2, default=str)
        elif format == "csv":
            import csv
            import io
            output = io.StringIO()
            if results:
                writer = csv.DictWriter(output, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
            return output.getvalue()
        else:
            return str(results)