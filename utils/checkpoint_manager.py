#!/usr/bin/env python3
"""
🔄 Checkpoint Manager - Session persistence and recovery utility
Author: wKayaa
Date: 2025-01-17

Manages scan progress, session persistence, and recovery for large-scale operations:
- Automatic checkpoint saving at configurable intervals
- Session recovery after interruptions
- Progress tracking and statistics
- Memory-efficient storage using compression
- Session cleanup and management
"""

import pickle
import gzip
import json
import uuid
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Union
from dataclasses import dataclass, field
import logging

@dataclass
class CheckpointMetadata:
    """Metadata for checkpoint files"""
    session_id: str
    creation_time: datetime
    last_update: datetime
    total_targets: int
    processed_targets: int
    progress_percentage: float
    scan_mode: str
    checkpoint_version: str = "1.0"
    
class CheckpointManager:
    """Advanced checkpoint management with compression and recovery"""
    
    def __init__(self, session_id: str, checkpoint_dir: Union[str, Path], 
                 auto_save_interval: int = 100, compression: bool = True,
                 max_checkpoints: int = 5):
        """
        Initialize checkpoint manager
        
        Args:
            session_id: Unique session identifier
            checkpoint_dir: Directory to store checkpoint files
            auto_save_interval: Number of processed items between auto-saves
            compression: Enable gzip compression for checkpoint files
            max_checkpoints: Maximum number of checkpoint files to keep
        """
        self.session_id = session_id
        self.checkpoint_dir = Path(checkpoint_dir)
        self.auto_save_interval = auto_save_interval
        self.compression = compression
        self.max_checkpoints = max_checkpoints
        
        # Create checkpoint directory
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.checkpoint_file = self.checkpoint_dir / f"checkpoint_{session_id}.pkl"
        self.metadata_file = self.checkpoint_dir / f"metadata_{session_id}.json"
        
        if compression:
            self.checkpoint_file = self.checkpoint_file.with_suffix(".pkl.gz")
        
        # Tracking
        self.last_save_time = datetime.utcnow()
        self.items_since_last_save = 0
        self.lock = threading.Lock()
        
        # Logger
        self.logger = logging.getLogger(f"CheckpointManager_{session_id}")
        
    def save_checkpoint(self, data: Dict[str, Any], force: bool = False) -> bool:
        """
        Save checkpoint data to disk
        
        Args:
            data: Dictionary containing checkpoint data
            force: Force save even if interval not reached
            
        Returns:
            bool: True if checkpoint was saved, False otherwise
        """
        with self.lock:
            self.items_since_last_save += 1
            
            # Check if we should save
            should_save = (
                force or 
                self.items_since_last_save >= self.auto_save_interval or
                (datetime.utcnow() - self.last_save_time).total_seconds() > 300  # 5 minutes
            )
            
            if not should_save:
                return False
            
            try:
                # Prepare checkpoint data
                checkpoint_data = {
                    'session_id': self.session_id,
                    'timestamp': datetime.utcnow(),
                    'data': data,
                    'version': '1.0'
                }
                
                # Save checkpoint file
                if self.compression:
                    with gzip.open(self.checkpoint_file, 'wb') as f:
                        pickle.dump(checkpoint_data, f, protocol=pickle.HIGHEST_PROTOCOL)
                else:
                    with open(self.checkpoint_file, 'wb') as f:
                        pickle.dump(checkpoint_data, f, protocol=pickle.HIGHEST_PROTOCOL)
                
                # Update metadata
                processed_count = len(data.get('processed_targets', []))
                total_count = data.get('total_targets', 0)
                progress = (processed_count / total_count * 100) if total_count > 0 else 0
                
                metadata = CheckpointMetadata(
                    session_id=self.session_id,
                    creation_time=checkpoint_data['timestamp'],
                    last_update=checkpoint_data['timestamp'],
                    total_targets=total_count,
                    processed_targets=processed_count,
                    progress_percentage=progress,
                    scan_mode=data.get('scan_mode', 'unknown')
                )
                
                self._save_metadata(metadata)
                
                # Reset counters
                self.last_save_time = datetime.utcnow()
                self.items_since_last_save = 0
                
                self.logger.info(f"✅ Checkpoint saved: {processed_count}/{total_count} targets ({progress:.1f}%)")
                
                # Clean up old checkpoints
                self._cleanup_old_checkpoints()
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Failed to save checkpoint: {e}")
                return False
    
    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """
        Load checkpoint data from disk
        
        Returns:
            Dict containing checkpoint data or None if no checkpoint exists
        """
        if not self.checkpoint_file.exists():
            self.logger.info("No checkpoint file found")
            return None
        
        try:
            if self.compression:
                with gzip.open(self.checkpoint_file, 'rb') as f:
                    checkpoint_data = pickle.load(f)
            else:
                with open(self.checkpoint_file, 'rb') as f:
                    checkpoint_data = pickle.load(f)
            
            # Validate checkpoint
            if not self._validate_checkpoint(checkpoint_data):
                self.logger.warning("⚠️ Invalid checkpoint data")
                return None
            
            self.logger.info(f"📂 Loaded checkpoint from {checkpoint_data['timestamp']}")
            return checkpoint_data['data']
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load checkpoint: {e}")
            return None
    
    def get_checkpoint_info(self) -> Optional[CheckpointMetadata]:
        """Get checkpoint metadata without loading full data"""
        if not self.metadata_file.exists():
            return None
        
        try:
            with open(self.metadata_file, 'r') as f:
                metadata_dict = json.load(f)
            
            return CheckpointMetadata(
                session_id=metadata_dict['session_id'],
                creation_time=datetime.fromisoformat(metadata_dict['creation_time']),
                last_update=datetime.fromisoformat(metadata_dict['last_update']),
                total_targets=metadata_dict['total_targets'],
                processed_targets=metadata_dict['processed_targets'],
                progress_percentage=metadata_dict['progress_percentage'],
                scan_mode=metadata_dict['scan_mode'],
                checkpoint_version=metadata_dict.get('checkpoint_version', '1.0')
            )
        except Exception as e:
            self.logger.error(f"Failed to load checkpoint metadata: {e}")
            return None
    
    def cleanup_checkpoint(self) -> bool:
        """Remove checkpoint files for this session"""
        try:
            files_removed = 0
            
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
                files_removed += 1
            
            if self.metadata_file.exists():
                self.metadata_file.unlink()
                files_removed += 1
            
            self.logger.info(f"🧹 Cleaned up {files_removed} checkpoint files")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup checkpoint: {e}")
            return False
    
    def list_checkpoints(self) -> List[CheckpointMetadata]:
        """List all available checkpoints in the directory"""
        checkpoints = []
        
        for metadata_file in self.checkpoint_dir.glob("metadata_*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    metadata_dict = json.load(f)
                
                metadata = CheckpointMetadata(
                    session_id=metadata_dict['session_id'],
                    creation_time=datetime.fromisoformat(metadata_dict['creation_time']),
                    last_update=datetime.fromisoformat(metadata_dict['last_update']),
                    total_targets=metadata_dict['total_targets'],
                    processed_targets=metadata_dict['processed_targets'],
                    progress_percentage=metadata_dict['progress_percentage'],
                    scan_mode=metadata_dict['scan_mode'],
                    checkpoint_version=metadata_dict.get('checkpoint_version', '1.0')
                )
                
                checkpoints.append(metadata)
                
            except Exception as e:
                self.logger.warning(f"Failed to load metadata from {metadata_file}: {e}")
        
        # Sort by last update time
        checkpoints.sort(key=lambda x: x.last_update, reverse=True)
        return checkpoints
    
    def cleanup_old_checkpoints(self, max_age_days: int = 7) -> int:
        """Clean up checkpoint files older than specified days"""
        cleaned = 0
        cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
        
        for checkpoint in self.list_checkpoints():
            if checkpoint.last_update < cutoff_time:
                try:
                    # Remove checkpoint files
                    checkpoint_file = self.checkpoint_dir / f"checkpoint_{checkpoint.session_id}.pkl"
                    if self.compression:
                        checkpoint_file = checkpoint_file.with_suffix(".pkl.gz")
                    
                    metadata_file = self.checkpoint_dir / f"metadata_{checkpoint.session_id}.json"
                    
                    if checkpoint_file.exists():
                        checkpoint_file.unlink()
                    
                    if metadata_file.exists():
                        metadata_file.unlink()
                    
                    cleaned += 1
                    self.logger.info(f"🧹 Removed old checkpoint: {checkpoint.session_id}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to remove checkpoint {checkpoint.session_id}: {e}")
        
        return cleaned
    
    def export_checkpoint(self, export_path: Union[str, Path], format: str = "json") -> bool:
        """
        Export checkpoint data to different formats
        
        Args:
            export_path: Path to export file
            format: Export format ("json", "csv", "yaml")
            
        Returns:
            bool: True if export successful
        """
        checkpoint_data = self.load_checkpoint()
        if not checkpoint_data:
            return False
        
        export_path = Path(export_path)
        
        try:
            if format.lower() == "json":
                # Convert datetime objects to ISO format
                serializable_data = self._make_serializable(checkpoint_data)
                
                with open(export_path, 'w') as f:
                    json.dump(serializable_data, f, indent=2)
            
            elif format.lower() == "yaml":
                try:
                    import yaml
                    serializable_data = self._make_serializable(checkpoint_data)
                    
                    with open(export_path, 'w') as f:
                        yaml.dump(serializable_data, f, default_flow_style=False)
                except ImportError:
                    self.logger.error("PyYAML not available for YAML export")
                    return False
            
            elif format.lower() == "csv":
                # Export as CSV (simplified view)
                import csv
                
                with open(export_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Target', 'Status', 'Timestamp'])
                    
                    processed = checkpoint_data.get('processed_targets', [])
                    for target in processed:
                        writer.writerow([target, 'Processed', checkpoint_data.get('timestamp', '')])
            
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return False
            
            self.logger.info(f"📤 Exported checkpoint to {export_path} ({format})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export checkpoint: {e}")
            return False
    
    def _save_metadata(self, metadata: CheckpointMetadata):
        """Save checkpoint metadata to JSON file"""
        metadata_dict = {
            'session_id': metadata.session_id,
            'creation_time': metadata.creation_time.isoformat(),
            'last_update': metadata.last_update.isoformat(),
            'total_targets': metadata.total_targets,
            'processed_targets': metadata.processed_targets,
            'progress_percentage': metadata.progress_percentage,
            'scan_mode': metadata.scan_mode,
            'checkpoint_version': metadata.checkpoint_version
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2)
    
    def _validate_checkpoint(self, checkpoint_data: Dict) -> bool:
        """Validate checkpoint data structure"""
        required_keys = ['session_id', 'timestamp', 'data']
        
        if not all(key in checkpoint_data for key in required_keys):
            return False
        
        if checkpoint_data['session_id'] != self.session_id:
            self.logger.warning(f"Session ID mismatch: expected {self.session_id}, got {checkpoint_data['session_id']}")
            return False
        
        return True
    
    def _cleanup_old_checkpoints(self):
        """Remove excess checkpoint files beyond max_checkpoints limit"""
        checkpoints = self.list_checkpoints()
        
        if len(checkpoints) <= self.max_checkpoints:
            return
        
        # Remove oldest checkpoints
        for checkpoint in checkpoints[self.max_checkpoints:]:
            try:
                checkpoint_file = self.checkpoint_dir / f"checkpoint_{checkpoint.session_id}.pkl"
                if self.compression:
                    checkpoint_file = checkpoint_file.with_suffix(".pkl.gz")
                
                metadata_file = self.checkpoint_dir / f"metadata_{checkpoint.session_id}.json"
                
                if checkpoint_file.exists():
                    checkpoint_file.unlink()
                
                if metadata_file.exists():
                    metadata_file.unlink()
                
                self.logger.debug(f"Removed excess checkpoint: {checkpoint.session_id}")
                
            except Exception as e:
                self.logger.error(f"Failed to remove excess checkpoint {checkpoint.session_id}: {e}")
    
    def _make_serializable(self, data: Any) -> Any:
        """Convert data to JSON-serializable format"""
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._make_serializable(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple, set)):
            return [self._make_serializable(item) for item in data]
        else:
            try:
                json.dumps(data)  # Test if serializable
                return data
            except (TypeError, ValueError):
                return str(data)  # Convert to string if not serializable

class SessionManager:
    """Manage multiple scanning sessions and their checkpoints"""
    
    def __init__(self, base_dir: Union[str, Path] = "./sessions"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("SessionManager")
    
    def create_session(self, session_id: Optional[str] = None, scan_mode: str = "unknown") -> CheckpointManager:
        """Create a new scanning session"""
        if not session_id:
            session_id = str(uuid.uuid4())[:8]
        
        session_dir = self.base_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        checkpoint_manager = CheckpointManager(
            session_id=session_id,
            checkpoint_dir=session_dir
        )
        
        self.logger.info(f"🆕 Created new session: {session_id}")
        return checkpoint_manager
    
    def get_session(self, session_id: str) -> Optional[CheckpointManager]:
        """Get existing session by ID"""
        session_dir = self.base_dir / session_id
        
        if not session_dir.exists():
            return None
        
        return CheckpointManager(
            session_id=session_id,
            checkpoint_dir=session_dir
        )
    
    def list_sessions(self) -> List[CheckpointMetadata]:
        """List all available sessions"""
        sessions = []
        
        for session_dir in self.base_dir.iterdir():
            if session_dir.is_dir():
                checkpoint_manager = CheckpointManager(
                    session_id=session_dir.name,
                    checkpoint_dir=session_dir
                )
                
                metadata = checkpoint_manager.get_checkpoint_info()
                if metadata:
                    sessions.append(metadata)
        
        sessions.sort(key=lambda x: x.last_update, reverse=True)
        return sessions
    
    def cleanup_sessions(self, max_age_days: int = 7) -> int:
        """Clean up old sessions"""
        cleaned = 0
        
        for session in self.list_sessions():
            cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
            
            if session.last_update < cutoff_time:
                session_dir = self.base_dir / session.session_id
                
                try:
                    import shutil
                    shutil.rmtree(session_dir)
                    cleaned += 1
                    self.logger.info(f"🧹 Removed old session: {session.session_id}")
                except Exception as e:
                    self.logger.error(f"Failed to remove session {session.session_id}: {e}")
        
        return cleaned

# Export for use in other modules
__all__ = ['CheckpointManager', 'SessionManager', 'CheckpointMetadata']

def main():
    """Example usage"""
    # Create session manager
    session_manager = SessionManager()
    
    # Create new session
    checkpoint_manager = session_manager.create_session("test_session")
    
    # Example data to checkpoint
    scan_data = {
        'total_targets': 1000,
        'processed_targets': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
        'scan_results': [
            {'ip': '192.168.1.1', 'status': 'accessible', 'services': ['http', 'ssh']},
            {'ip': '192.168.1.2', 'status': 'filtered'},
            {'ip': '192.168.1.3', 'status': 'accessible', 'services': ['http']}
        ],
        'scan_mode': 'balanced',
        'timestamp': datetime.utcnow()
    }
    
    # Save checkpoint
    checkpoint_manager.save_checkpoint(scan_data, force=True)
    
    # Load checkpoint
    loaded_data = checkpoint_manager.load_checkpoint()
    print(f"Loaded {len(loaded_data['processed_targets'])} processed targets")
    
    # List all sessions
    sessions = session_manager.list_sessions()
    print(f"Found {len(sessions)} sessions")
    
    for session in sessions:
        print(f"Session {session.session_id}: {session.progress_percentage:.1f}% complete")

if __name__ == "__main__":
    main()