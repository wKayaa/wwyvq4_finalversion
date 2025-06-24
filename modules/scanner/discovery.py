#!/usr/bin/env python3
"""
🔍 K8s Discovery Scanner - Phase 1
Advanced Kubernetes cluster discovery with comprehensive detection

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Optional
from ipaddress import IPv4Network, IPv4Address


class K8sDiscoveryScanner:
    """Advanced Kubernetes cluster discovery scanner"""
    
    def __init__(self, timeout: int = 15, max_concurrent: int = 100, error_handler=None):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.error_handler = error_handler
        
        # Extended Kubernetes ports based on real-world deployments
        self.k8s_ports = [6443, 8443, 443, 80, 8080, 8001, 8888, 9443, 10250, 10251, 10252, 2379, 2380]
        
        # Kubernetes detection patterns
        self.k8s_indicators = [
            "kubernetes", "k8s", "apiVersion", "unauthorized", "forbidden",
            "kube-apiserver", "etcd", "kubelet", "cluster-admin", "kube-system",
            "default-token", "serviceaccount", "Bearer", "kubectl"
        ]
        
        # User agents for stealth scanning
        self.user_agents = [
            "Mozilla/5.0 (compatible; Kubernetes-Health-Check/1.0)",
            "kubectl/v1.24.0", 
            "kube-probe/1.0",
            "Mozilla/5.0 (compatible; F8S-Scanner/2.0)"
        ]
        
    async def scan_target(self, target: str) -> Dict:
        """Scan a single target for Kubernetes clusters with enhanced detection"""
        clusters = []
        
        # Expand target if it's a CIDR
        targets = self._expand_target(target)
        
        for single_target in targets[:5]:  # Limit to first 5 IPs for performance
            # Scan common ports for Kubernetes API endpoints
            for port in self.k8s_ports:
                cluster_info = await self._check_k8s_port(single_target, port)
                if cluster_info:
                    clusters.append(cluster_info)
        
        return {"target": target, "clusters": clusters}
    
    def _expand_target(self, target: str) -> List[str]:
        """Expand CIDR ranges to individual IPs"""
        try:
            if '/' in target:
                network = IPv4Network(target, strict=False)
                # Limit expansion for performance
                return [str(ip) for ip in list(network.hosts())[:10]]
            else:
                return [target]
        except Exception:
            return [target]
    
    async def _check_k8s_port(self, target: str, port: int) -> Optional[Dict]:
        """Check specific port for Kubernetes services"""
        
        # Try HTTPS first, then HTTP
        for protocol in ["https", "http"]:
            endpoint = f"{protocol}://{target}:{port}"
            
            cluster_info = await self._check_k8s_endpoint(endpoint, target, port, protocol)
            if cluster_info:
                return cluster_info
        
        return None
    
    async def _check_k8s_endpoint(self, endpoint: str, target: str, port: int, protocol: str) -> Optional[Dict]:
        """Enhanced Kubernetes endpoint detection"""
        
        try:
            connector = aiohttp.TCPConnector(
                ssl=False,
                limit=100,
                limit_per_host=30,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=5,
                sock_read=5
            )
            
            headers = {
                "User-Agent": self.user_agents[0],
                "Accept": "application/json, */*",
                "Connection": "close"
            }
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=headers
            ) as session:
                
                # Multiple detection methods
                detection_methods = [
                    self._check_api_paths,
                    self._check_metrics_endpoints,
                    self._check_health_endpoints,
                    self._check_version_endpoints
                ]
                
                for method in detection_methods:
                    result = await method(session, endpoint)
                    if result:
                        return {
                            "endpoint": endpoint,
                            "target": target,
                            "port": port,
                            "protocol": protocol,
                            "status": "accessible",
                            "detection_method": method.__name__,
                            "version": result.get("version", "unknown"),
                            "cluster_info": result.get("cluster_info", {}),
                            "vulnerabilities": await self._check_basic_vulnerabilities(session, endpoint)
                        }
        
        except Exception:
            pass
        
        return None
    
    async def _check_api_paths(self, session: aiohttp.ClientSession, endpoint: str) -> Optional[Dict]:
        """Check standard Kubernetes API paths"""
        api_paths = [
            "/api", "/api/v1", "/apis", "/openapi/v2", "/version",
            "/api/v1/namespaces", "/api/v1/nodes", "/api/v1/pods"
        ]
        
        for path in api_paths:
            try:
                async with session.get(f"{endpoint}{path}") as response:
                    if response.status in [200, 401, 403]:
                        text = await response.text()
                        
                        # Check for Kubernetes indicators
                        if any(indicator in text.lower() for indicator in self.k8s_indicators):
                            version_info = self._extract_version_info(text, response.headers)
                            return {
                                "path": path,
                                "status_code": response.status,
                                "version": version_info.get("version"),
                                "cluster_info": version_info
                            }
            except Exception:
                continue
        
        return None
    
    async def _check_metrics_endpoints(self, session: aiohttp.ClientSession, endpoint: str) -> Optional[Dict]:
        """Check Kubernetes metrics endpoints"""
        metrics_paths = ["/metrics", "/stats", "/healthz", "/livez", "/readyz"]
        
        for path in metrics_paths:
            try:
                async with session.get(f"{endpoint}{path}") as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        # Check for Kubernetes metrics patterns
                        if any(pattern in text for pattern in [
                            "kubernetes_", "kubelet_", "apiserver_", "kube_"
                        ]):
                            return {
                                "path": path,
                                "status_code": response.status,
                                "type": "metrics_endpoint"
                            }
            except Exception:
                continue
        
        return None
    
    async def _check_health_endpoints(self, session: aiohttp.ClientSession, endpoint: str) -> Optional[Dict]:
        """Check Kubernetes health endpoints"""
        health_paths = ["/healthz", "/livez", "/readyz", "/health"]
        
        for path in health_paths:
            try:
                async with session.get(f"{endpoint}{path}") as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        if "ok" in text.lower() or "healthy" in text.lower():
                            return {
                                "path": path,
                                "status_code": response.status,
                                "type": "health_endpoint"
                            }
            except Exception:
                continue
        
        return None
    
    async def _check_version_endpoints(self, session: aiohttp.ClientSession, endpoint: str) -> Optional[Dict]:
        """Check Kubernetes version endpoints"""
        version_paths = ["/version", "/api/v1/version"]
        
        for path in version_paths:
            try:
                async with session.get(f"{endpoint}{path}") as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            if "major" in data or "minor" in data or "gitVersion" in data:
                                return {
                                    "path": path,
                                    "status_code": response.status,
                                    "version": data.get("gitVersion", "unknown"),
                                    "cluster_info": data
                                }
                        except Exception:
                            pass
            except Exception:
                continue
        
        return None
    
    def _extract_version_info(self, response_text: str, headers: Dict) -> Dict:
        """Extract Kubernetes version information"""
        version_info = {}
        
        # Extract from response text
        version_patterns = [
            r'"gitVersion":"([^"]+)"',
            r'"major":"([^"]+)".*"minor":"([^"]+)"',
            r'kubernetes[:/\s]+v?([0-9]+\.[0-9]+\.[0-9]+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                version_info["version"] = match.group(1)
                break
        
        # Extract from headers
        server_header = headers.get("Server", "")
        if "kubernetes" in server_header.lower():
            version_info["server"] = server_header
        
        return version_info
    
    async def _check_basic_vulnerabilities(self, session: aiohttp.ClientSession, endpoint: str) -> List[str]:
        """Check for basic Kubernetes vulnerabilities"""
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
        
        # Check for kubelet endpoints
        if ":10250" in endpoint:
            try:
                async with session.get(f"{endpoint}/stats/summary") as response:
                    if response.status == 200:
                        vulnerabilities.append("exposed_kubelet_stats")
            except Exception:
                pass
        
        return vulnerabilities