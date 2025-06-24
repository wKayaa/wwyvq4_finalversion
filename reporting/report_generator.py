#!/usr/bin/env python3
"""
📊 Report Generator
Generate reports and exports for F8S Framework

Author: wKayaa
Date: 2025-01-28
"""

import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, output_dir: str = "./results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_report(self, results, stats: Dict, format: str = "json"):
        """Generate report in specified format"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        session_id = results.session_id[:8]
        
        report_data = {
            "session_info": {
                "session_id": results.session_id,
                "mode": results.mode,
                "start_time": results.start_time.isoformat(),
                "end_time": results.end_time.isoformat(),
                "duration_seconds": (results.end_time - results.start_time).total_seconds(),
                "success": results.success
            },
            "summary": {
                "targets_processed": results.targets_processed,
                "clusters_found": results.clusters_found,
                "clusters_exploited": results.clusters_exploited,
                "credentials_extracted": results.credentials_extracted,
                "credentials_validated": results.credentials_validated,
                "persistent_access": results.persistent_access,
                "notifications_sent": results.notifications_sent
            },
            "detailed_stats": stats,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        if format == "json":
            await self._generate_json_report(report_data, session_id, timestamp)
        elif format == "csv":
            await self._generate_csv_report(report_data, session_id, timestamp)
        elif format == "xml":
            await self._generate_xml_report(report_data, session_id, timestamp)
    
    async def _generate_json_report(self, data: Dict, session_id: str, timestamp: str):
        """Generate JSON report"""
        filename = f"f8s_report_{session_id}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"📄 JSON report: {filepath}")
    
    async def _generate_csv_report(self, data: Dict, session_id: str, timestamp: str):
        """Generate CSV report"""
        filename = f"f8s_report_{session_id}_{timestamp}.csv"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(["Metric", "Value"])
            
            # Write session info
            for key, value in data["session_info"].items():
                writer.writerow([f"session_{key}", value])
            
            # Write summary
            for key, value in data["summary"].items():
                writer.writerow([key, value])
        
        print(f"📄 CSV report: {filepath}")
    
    async def _generate_xml_report(self, data: Dict, session_id: str, timestamp: str):
        """Generate XML report"""
        filename = f"f8s_report_{session_id}_{timestamp}.xml"
        filepath = self.output_dir / filename
        
        root = ET.Element("f8s_report")
        
        # Add session info
        session_elem = ET.SubElement(root, "session_info")
        for key, value in data["session_info"].items():
            elem = ET.SubElement(session_elem, key)
            elem.text = str(value)
        
        # Add summary
        summary_elem = ET.SubElement(root, "summary")
        for key, value in data["summary"].items():
            elem = ET.SubElement(summary_elem, key)
            elem.text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        print(f"📄 XML report: {filepath}")