#!/usr/bin/env python3
"""
🔍 K8s Discovery Scanner - Phase 1
Discovers Kubernetes clusters and services

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional


class K8sDiscoveryScanner:
    """Kubernetes cluster discovery scanner"""
    
    def __init__(self, timeout: int = 15, max_concurrent: int = 100, error_handler=None):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.error_handler = error_handler
        
        # Common Kubernetes ports
        self.k8s_ports = [6443, 8443, 443, 80, 8080, 8001, 8888]
        
    async def scan_target(self, target: str) -> Dict:
        """Scan a single target for Kubernetes clusters"""
        clusters = []
        
        # Scan common ports for Kubernetes API endpoints
        for port in self.k8s_ports:
            endpoint = f"https://{target}:{port}"
            
            try:
                if await self._check_k8s_endpoint(endpoint):
                    clusters.append({
                        "endpoint": endpoint,
                        "target": target,
                        "port": port,
                        "protocol": "https",
                        "status": "accessible"
                    })
            except Exception:
                # Try HTTP fallback
                endpoint_http = f"http://{target}:{port}"
                try:
                    if await self._check_k8s_endpoint(endpoint_http):
                        clusters.append({
                            "endpoint": endpoint_http,
                            "target": target,
                            "port": port,
                            "protocol": "http",
                            "status": "accessible"
                        })
                except Exception:
                    pass  # Skip failed endpoints
        
        return {"target": target, "clusters": clusters}
    
    async def _check_k8s_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is a Kubernetes API server"""
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                
                # Check common Kubernetes paths
                k8s_paths = ["/api", "/api/v1", "/version", "/readyz", "/livez"]
                
                for path in k8s_paths:
                    try:
                        async with session.get(f"{endpoint}{path}") as response:
                            # Check for Kubernetes-specific indicators
                            if response.headers.get("Server", "").lower().find("kubernetes") != -1:
                                return True
                            
                            # Check response content for Kubernetes indicators
                            if response.status in [200, 401, 403]:
                                text = await response.text()
                                if any(indicator in text.lower() for indicator in [
                                    "kubernetes", "k8s", "apiVersion", "unauthorized"
                                ]):
                                    return True
                    
                    except Exception:
                        continue
        
        except Exception:
            pass
        
        return False