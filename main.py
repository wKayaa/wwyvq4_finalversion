#!/usr/bin/env python3
"""
🚀 F8S Framework - Single Entry Point
Author: wKayaa
Date: 2025-01-28

Complete refactored framework with unified pipeline:
scan → exploit → extract → validate → notify
"""

import asyncio
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

# Core imports
from core.orchestrator import F8SOrchestrator
from core.session_manager import SessionManager
from core.error_handler import ErrorHandler
from config.settings import load_config, validate_config

def parse_arguments():
    """Parse command line arguments with full F8S options"""
    parser = argparse.ArgumentParser(
        description='🚀 F8S Framework - Kubernetes Exploitation Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Massive scan with Telegram notifications
  python3 main.py --targets targets.txt --threads 500 --telegram-token TOKEN --mode all

  # Mail services focused exploitation  
  python3 main.py --targets 192.168.1.0/24 --mode mail --threads 200

  # Stealth mode with web interface
  python3 main.py --targets example.com --mode stealth --threads 5 --web

  # Single target aggressive mode
  python3 main.py --target 10.0.0.1 --mode aggressive --threads 100
        '''
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target', '-t', help='Single target (IP/domain/CIDR)')
    target_group.add_argument('--targets', '-f', help='Target file path')
    
    # Core options
    parser.add_argument('--mode', '-m', 
                       choices=['scan', 'exploit', 'mail', 'stealth', 'aggressive', 'all'], 
                       default='exploit', 
                       help='Operation mode')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of concurrent threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=15,
                       help='Timeout per operation in seconds (default: 15)')
    
    # Interface options
    parser.add_argument('--web', action='store_true',
                       help='Start web interface on port 5000')
    parser.add_argument('--api', action='store_true',
                       help='Start API server on port 8080')
    
    # Integration options
    parser.add_argument('--telegram-token', help='Telegram bot token for notifications')
    parser.add_argument('--telegram-chat', help='Telegram chat ID')
    parser.add_argument('--discord-webhook', help='Discord webhook URL')
    
    # Output options
    parser.add_argument('--output', '-o', default='./results',
                       help='Output directory (default: ./results)')
    parser.add_argument('--config', '-c', default='config/f8s_config.yaml',
                       help='Configuration file')
    parser.add_argument('--export-format', choices=['json', 'csv', 'xml'], 
                       default='json', help='Export format')
    
    # Advanced options
    parser.add_argument('--retry-count', type=int, default=3,
                       help='Retry count for failed operations')
    parser.add_argument('--skip-validation', action='store_true',
                       help='Skip credential validation phase')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Skip cleanup phase')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--debug', action='store_true',
                       help='Debug mode')
    
    return parser.parse_args()

async def main():
    """Main entry point for F8S Framework"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Display banner
        print_banner(args)
        
        # Load and validate configuration
        config = load_config(args.config)
        if not validate_config(config):
            print("❌ Configuration validation failed")
            return 1
        
        # Initialize session manager
        session_manager = SessionManager()
        session_id = session_manager.create_session(args.mode)
        
        # Initialize error handler
        error_handler = ErrorHandler(
            retry_count=args.retry_count,
            skip_on_fail=True,
            verbose=args.verbose
        )
        
        # Initialize orchestrator
        orchestrator = F8SOrchestrator(
            config=config,
            session_manager=session_manager,
            error_handler=error_handler,
            args=args
        )
        
        # Load targets
        targets = await load_targets(args)
        if not targets:
            print("❌ No valid targets loaded")
            return 1
        
        print(f"🎯 Loaded {len(targets)} targets")
        
        # Initialize orchestrator systems
        await orchestrator.initialize()
        
        # Start web/API interfaces if requested
        if args.web:
            await orchestrator.start_web_interface()
        
        if args.api:
            await orchestrator.start_api_server()
        
        # Execute unified pipeline based on mode
        print(f"🚀 Starting F8S pipeline in {args.mode.upper()} mode...")
        results = await orchestrator.run_pipeline(targets, args.mode)
        
        # Generate reports and notifications
        await orchestrator.generate_reports(results)
        
        # Cleanup if requested
        if not args.no_cleanup:
            await orchestrator.cleanup()
        
        print("✅ F8S Framework execution completed successfully")
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️ Operation interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Critical error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def print_banner(args):
    """Display F8S Framework banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                    🚀 F8S FRAMEWORK v2.0                            ║
║               Kubernetes Exploitation Pipeline                       ║
║                        Author: wKayaa                                ║
║                   {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Mode: {args.mode.upper()}
🎢 Pipeline: scan → exploit → extract → validate → notify
📊 Threads: {args.threads}
⏱️  Timeout: {args.timeout}s
🌐 Web UI: {'✅' if args.web else '❌'}
🔌 API: {'✅' if args.api else '❌'}  
📱 Telegram: {'✅' if args.telegram_token else '❌'}
🎵 Discord: {'✅' if args.discord_webhook else '❌'}
"""
    print(banner)


async def load_targets(args):
    """Load targets from file or single target"""
    targets = []
    
    if args.target:
        targets.append(args.target)
    elif args.targets:
        try:
            target_file = Path(args.targets)
            if not target_file.exists():
                print(f"❌ Target file not found: {args.targets}")
                return []
            
            with open(target_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except Exception as e:
            print(f"❌ Error loading targets: {str(e)}")
            return []
    
    return targets

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
