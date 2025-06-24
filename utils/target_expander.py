#!/usr/bin/env python3
"""
🎯 Target Expander
Expand target specifications (CIDR, ranges, etc.)

Author: wKayaa
Date: 2025-01-28
"""

import ipaddress
from typing import List


class TargetExpander:
    """Expand target specifications"""
    
    async def expand_targets(self, targets: List[str]) -> List[str]:
        """Expand target list from various formats"""
        expanded = []
        
        for target in targets:
            try:
                # Check if it's a CIDR range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        expanded.append(str(ip))
                else:
                    expanded.append(target)
            except Exception:
                # Not a valid CIDR, treat as hostname/IP
                expanded.append(target)
        
        return expanded