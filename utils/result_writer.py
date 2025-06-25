#!/usr/bin/env python3
"""
📝 Result Writer
Memory-efficient result writing for large-scale scanning operations

Author: wKayaa
Date: 2025-01-28
"""

import json
import csv
import gzip
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, BinaryIO
from dataclasses import asdict
import threading


class ResultWriter:
    """Memory-efficient result writer that streams results to disk"""
    
    def __init__(self, output_dir: Path, session_id: str, compress: bool = True):
        self.output_dir = Path(output_dir)
        self.session_id = session_id
        self.compress = compress
        self.logger = logging.getLogger("ResultWriter")
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # File handles for streaming
        self._json_file: Optional[TextIO] = None
        self._csv_file: Optional[TextIO] = None
        self._csv_writer: Optional[csv.DictWriter] = None
        self._result_count = 0
        self._lock = threading.Lock()
        
        # Initialize files
        self._init_files()
    
    def _init_files(self):
        """Initialize output files"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # JSON file for detailed results
        json_filename = f"{self.session_id}_{timestamp}_results.json"
        if self.compress:
            json_filename += ".gz"
        
        json_path = self.output_dir / json_filename
        
        if self.compress:
            self._json_file = gzip.open(json_path, 'wt', encoding='utf-8')
        else:
            self._json_file = open(json_path, 'w', encoding='utf-8')
        
        # Write JSON array start
        self._json_file.write('[\n')
        
        # CSV file for summary data
        csv_filename = f"{self.session_id}_{timestamp}_summary.csv"
        csv_path = self.output_dir / csv_filename
        self._csv_file = open(csv_path, 'w', newline='', encoding='utf-8')
        
        # CSV headers will be written on first result
        
        self.logger.info(f"📄 Results will be written to {json_path}")
        self.logger.info(f"📊 Summary will be written to {csv_path}")
    
    def write_result(self, result: Any):
        """Write a single result to files"""
        with self._lock:
            try:
                # Convert result to dictionary if it's a dataclass
                if hasattr(result, '__dataclass_fields__'):
                    result_dict = asdict(result)
                elif hasattr(result, '__dict__'):
                    result_dict = result.__dict__
                else:
                    result_dict = result
                
                # Write to JSON file
                if self._result_count > 0:
                    self._json_file.write(',\n')
                
                json.dump(result_dict, self._json_file, indent=2, default=str)
                
                # Write to CSV file
                if self._csv_writer is None:
                    # Initialize CSV writer with headers from first result
                    fieldnames = self._flatten_dict(result_dict).keys()
                    self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
                    self._csv_writer.writeheader()
                
                # Flatten nested dictionaries for CSV
                flattened = self._flatten_dict(result_dict)
                self._csv_writer.writerow(flattened)
                
                self._result_count += 1
                
                # Flush every 100 results
                if self._result_count % 100 == 0:
                    self._json_file.flush()
                    self._csv_file.flush()
                    
            except Exception as e:
                self.logger.error(f"Failed to write result: {e}")
    
    def write_batch(self, results: List[Any]):
        """Write a batch of results efficiently"""
        for result in results:
            self.write_result(result)
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary for CSV writing"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to comma-separated strings
                items.append((new_key, ','.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def write_stats(self, stats: Dict[str, Any]):
        """Write final statistics"""
        stats_file = self.output_dir / f"{self.session_id}_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        
        self.logger.info(f"📈 Statistics written to {stats_file}")
    
    def close(self):
        """Close all file handles"""
        with self._lock:
            try:
                if self._json_file:
                    # Close JSON array
                    self._json_file.write('\n]')
                    self._json_file.close()
                    self._json_file = None
                
                if self._csv_file:
                    self._csv_file.close()
                    self._csv_file = None
                
                self.logger.info(f"✅ Wrote {self._result_count:,} results to disk")
                
            except Exception as e:
                self.logger.error(f"Error closing result writer: {e}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    @property
    def result_count(self) -> int:
        """Get current result count"""
        return self._result_count