#!/usr/bin/env python3
"""
🎯 F8S Session Manager
Manages session tracking and state for F8S Framework

Author: wKayaa
Date: 2025-01-28
"""

import time
import uuid
from datetime import datetime
from typing import Dict, Optional, List
from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass
class Session:
    """Session information tracking"""
    session_id: str
    mode: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "active"  # active, completed, failed, interrupted
    targets_count: int = 0
    results: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


class SessionManager:
    """Manages F8S Framework sessions"""
    
    def __init__(self, sessions_dir: str = "./sessions"):
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(exist_ok=True)
        
        self.current_session_id: Optional[str] = None
        self.sessions: Dict[str, Session] = {}
        
        # Load existing sessions
        self._load_existing_sessions()
    
    def create_session(self, mode: str, metadata: Dict = None) -> str:
        """Create a new session"""
        session_id = f"f8s_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        
        session = Session(
            session_id=session_id,
            mode=mode,
            start_time=datetime.utcnow(),
            metadata=metadata or {}
        )
        
        self.sessions[session_id] = session
        self.current_session_id = session_id
        
        # Save session to disk
        self._save_session(session)
        
        print(f"🆔 Created session: {session_id}")
        return session_id
    
    def get_current_session(self) -> Optional[str]:
        """Get current active session ID"""
        return self.current_session_id
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def update_session(self, session_id: str, **kwargs):
        """Update session data"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
                else:
                    session.metadata[key] = value
            
            self._save_session(session)
    
    def complete_session(self, session_id: str, results: Dict = None):
        """Mark session as completed"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.end_time = datetime.utcnow()
            session.status = "completed"
            
            if results:
                session.results = results
            
            self._save_session(session)
            print(f"✅ Session completed: {session_id}")
    
    def fail_session(self, session_id: str, error_message: str):
        """Mark session as failed"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.end_time = datetime.utcnow()
            session.status = "failed"
            session.metadata["error_message"] = error_message
            
            self._save_session(session)
            print(f"❌ Session failed: {session_id}")
    
    def interrupt_session(self, session_id: str):
        """Mark session as interrupted"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.end_time = datetime.utcnow()
            session.status = "interrupted"
            
            self._save_session(session)
            print(f"⏹️ Session interrupted: {session_id}")
    
    def list_sessions(self, status: Optional[str] = None) -> List[Session]:
        """List sessions, optionally filtered by status"""
        sessions = list(self.sessions.values())
        
        if status:
            sessions = [s for s in sessions if s.status == status]
        
        return sorted(sessions, key=lambda x: x.start_time, reverse=True)
    
    def get_session_stats(self, session_id: str) -> Dict:
        """Get session statistics"""
        session = self.get_session(session_id)
        if not session:
            return {}
        
        duration = None
        if session.end_time:
            duration = (session.end_time - session.start_time).total_seconds()
        
        return {
            "session_id": session.session_id,
            "mode": session.mode,
            "status": session.status,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "duration_seconds": duration,
            "targets_count": session.targets_count,
            "results_summary": {
                "clusters_found": session.results.get("clusters_found", 0),
                "clusters_exploited": session.results.get("clusters_exploited", 0),
                "credentials_extracted": session.results.get("credentials_extracted", 0),
                "credentials_validated": session.results.get("credentials_validated", 0)
            },
            "metadata": session.metadata
        }
    
    def cleanup_old_sessions(self, max_age_days: int = 30):
        """Remove old session files"""
        cutoff_time = datetime.utcnow().timestamp() - (max_age_days * 24 * 60 * 60)
        
        removed_count = 0
        for session_file in self.sessions_dir.glob("session_*.json"):
            if session_file.stat().st_mtime < cutoff_time:
                session_file.unlink()
                removed_count += 1
        
        print(f"🧹 Cleaned up {removed_count} old session files")
    
    def _save_session(self, session: Session):
        """Save session to disk"""
        session_file = self.sessions_dir / f"session_{session.session_id}.json"
        
        session_data = {
            "session_id": session.session_id,
            "mode": session.mode,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "status": session.status,
            "targets_count": session.targets_count,
            "results": session.results,
            "metadata": session.metadata
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
    
    def _load_existing_sessions(self):
        """Load existing sessions from disk"""
        session_files = self.sessions_dir.glob("session_*.json")
        
        for session_file in session_files:
            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                
                session = Session(
                    session_id=session_data["session_id"],
                    mode=session_data["mode"],
                    start_time=datetime.fromisoformat(session_data["start_time"]),
                    end_time=datetime.fromisoformat(session_data["end_time"]) if session_data.get("end_time") else None,
                    status=session_data.get("status", "active"),
                    targets_count=session_data.get("targets_count", 0),
                    results=session_data.get("results", {}),
                    metadata=session_data.get("metadata", {})
                )
                
                self.sessions[session.session_id] = session
                
            except Exception as e:
                print(f"⚠️ Failed to load session from {session_file}: {str(e)}")
    
    def export_session(self, session_id: str, export_path: str) -> bool:
        """Export session data to file"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        try:
            session_stats = self.get_session_stats(session_id)
            
            with open(export_path, 'w') as f:
                json.dump(session_stats, f, indent=2)
            
            print(f"📊 Session exported to: {export_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to export session: {str(e)}")
            return False