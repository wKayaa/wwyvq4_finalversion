#!/usr/bin/env python3
"""
🚀 WWYVQ Large Scale Configuration Loader
Automatically loads optimized configurations for different scales

Author: wKayaa
Date: 2025-01-17
"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class LargeScaleConfig:
    """Large scale configuration container"""
    system: Dict[str, Any]
    network: Dict[str, Any]
    scanning: Dict[str, Any]
    checkpointing: Dict[str, Any]
    telegram: Dict[str, Any]
    logging: Dict[str, Any]
    statistics: Dict[str, Any]
    output: Dict[str, Any]
    security: Dict[str, Any]
    monitoring: Dict[str, Any]
    advanced: Dict[str, Any]


class ConfigurationLoader:
    """Load and optimize configuration for different scales"""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
    def load_large_scale_config(self) -> LargeScaleConfig:
        """Load large scale configuration from YAML file"""
        config_file = self.config_dir / "large_scale_config.yaml"
        
        if not config_file.exists():
            raise FileNotFoundError(f"Large scale config not found: {config_file}")
        
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return LargeScaleConfig(
            system=config_data.get('system', {}),
            network=config_data.get('network', {}),
            scanning=config_data.get('scanning', {}),
            checkpointing=config_data.get('checkpointing', {}),
            telegram=config_data.get('telegram', {}),
            logging=config_data.get('logging', {}),
            statistics=config_data.get('statistics', {}),
            output=config_data.get('output', {}),
            security=config_data.get('security', {}),
            monitoring=config_data.get('monitoring', {}),
            advanced=config_data.get('advanced', {})
        )
    
    def create_scanner_config(self, target_count: int, config: Optional[LargeScaleConfig] = None):
        """Create optimized scanner configuration based on target count"""
        if config is None:
            config = self.load_large_scale_config()
        
        # Import here to avoid circular imports
        from k8s_scanner_ultimate import ScannerConfig, ScanMode, ValidationType
        
        # Determine mode based on target count
        if target_count > 10000000:  # 10M+
            mode = ScanMode.ULTIMATE
            max_concurrent = config.system.get('max_concurrent_threads', 10000)
            batch_size = config.system.get('batch_size', 50000)
        elif target_count > 1000000:  # 1M+
            mode = ScanMode.AGGRESSIVE
            max_concurrent = min(5000, config.system.get('max_concurrent_threads', 5000))
            batch_size = config.system.get('batch_size', 20000)
        elif target_count > 100000:  # 100K+
            mode = ScanMode.BALANCED
            max_concurrent = min(2000, config.system.get('max_concurrent_threads', 2000))
            batch_size = config.system.get('batch_size', 10000)
        else:
            mode = ScanMode.BALANCED
            max_concurrent = min(500, config.system.get('max_concurrent_threads', 500))
            batch_size = config.system.get('batch_size', 5000)
        
        return ScannerConfig(
            mode=mode,
            max_concurrent=max_concurrent,
            timeout=config.system.get('timeout_per_operation', 10),
            validation_type=ValidationType.BASIC,
            enable_checkpoint=config.checkpointing.get('enable_checkpoints', True),
            checkpoint_interval=config.checkpointing.get('checkpoint_interval', 5000),
            rate_limit_per_second=config.system.get('requests_per_second', 1000),
            
            # Large scale optimizations
            large_scale_mode=target_count > 100000,
            max_concurrent_large_scale=config.system.get('max_concurrent_threads', 10000),
            batch_size=batch_size,
            connection_pool_size=config.network.get('tcp_connector_limit', 2000),
            memory_limit_mb=config.system.get('memory_limit_gb', 16) * 1024,
            enable_memory_monitoring=config.monitoring.get('enable_monitoring', True),
            enable_adaptive_rate_limiting=config.system.get('adaptive_rate_limiting', True),
            tcp_keepalive_timeout=config.network.get('tcp_keepalive_timeout', 60),
            dns_cache_size=config.network.get('dns_cache_size', 10000),
            max_retries=config.network.get('max_retries', 2)
        )
    
    def create_telegram_config(self, config: Optional[LargeScaleConfig] = None):
        """Create Telegram rate limiting configuration"""
        if config is None:
            config = self.load_large_scale_config()
        
        # Import here to avoid circular imports
        from telegram_mail_enhanced import TelegramRateLimitConfig
        
        return TelegramRateLimitConfig(
            max_messages_per_minute=config.telegram.get('max_messages_per_minute', 20),
            max_messages_per_hour=config.telegram.get('max_messages_per_hour', 200),
            batch_size=config.telegram.get('batch_size', 100),
            batch_interval=config.telegram.get('batch_interval', 300),
            progress_interval=config.telegram.get('progress_interval', 10000),
            enable_batching=config.telegram.get('batch_notifications', True),
            only_validated_credentials=config.telegram.get('only_validated_credentials', True)
        )
    
    def get_system_recommendations(self, target_count: int) -> Dict[str, Any]:
        """Get system configuration recommendations based on target count"""
        if target_count > 10000000:  # 10M+
            return {
                "cpu_cores": "32+",
                "memory_gb": "64+",
                "network_bandwidth": "10Gbps+",
                "storage_type": "NVMe SSD",
                "storage_capacity": "2TB+",
                "os_recommendations": [
                    "Linux Ubuntu 20.04+ or CentOS 8+",
                    "Kernel 5.4+",
                    "Docker 20.10+ (if containerized)"
                ],
                "system_limits": {
                    "ulimit_files": 1000000,
                    "ulimit_processes": 32768,
                    "net.core.somaxconn": 65535,
                    "net.ipv4.ip_local_port_range": "1024 65535",
                    "vm.max_map_count": 262144
                },
                "docker_settings": {
                    "memory": "64g",
                    "cpus": "32",
                    "ulimits": "nofile=1000000:1000000",
                    "network": "host"
                }
            }
        elif target_count > 1000000:  # 1M+
            return {
                "cpu_cores": "16+",
                "memory_gb": "32+",
                "network_bandwidth": "1Gbps+",
                "storage_type": "SSD",
                "storage_capacity": "500GB+",
                "os_recommendations": [
                    "Linux Ubuntu 18.04+ or CentOS 7+",
                    "Kernel 4.15+",
                    "Docker 19.03+ (if containerized)"
                ],
                "system_limits": {
                    "ulimit_files": 500000,
                    "ulimit_processes": 16384,
                    "net.core.somaxconn": 32768,
                    "net.ipv4.ip_local_port_range": "1024 65535",
                    "vm.max_map_count": 131072
                },
                "docker_settings": {
                    "memory": "32g",
                    "cpus": "16",
                    "ulimits": "nofile=500000:500000",
                    "network": "host"
                }
            }
        else:
            return {
                "cpu_cores": "8+",
                "memory_gb": "16+",
                "network_bandwidth": "100Mbps+",
                "storage_type": "SSD",
                "storage_capacity": "100GB+",
                "os_recommendations": [
                    "Linux Ubuntu 18.04+ or CentOS 7+",
                    "Docker 19.03+ (if containerized)"
                ],
                "system_limits": {
                    "ulimit_files": 100000,
                    "ulimit_processes": 8192,
                    "net.core.somaxconn": 16384
                },
                "docker_settings": {
                    "memory": "16g",
                    "cpus": "8",
                    "ulimits": "nofile=100000:100000"
                }
            }
    
    def validate_system_configuration(self) -> Dict[str, bool]:
        """Validate current system configuration for large scale operations"""
        validation_results = {}
        
        try:
            import psutil
            import os
            
            # Check available memory
            memory_gb = psutil.virtual_memory().total / (1024**3)
            validation_results["sufficient_memory"] = memory_gb >= 16
            
            # Check CPU cores
            cpu_cores = psutil.cpu_count()
            validation_results["sufficient_cpu"] = cpu_cores >= 8
            
            # Check disk space
            disk_usage = psutil.disk_usage('/')
            free_gb = disk_usage.free / (1024**3)
            validation_results["sufficient_disk"] = free_gb >= 50
            
            # Check file descriptor limit
            try:
                import resource
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                validation_results["file_descriptors_ok"] = soft >= 65536
            except:
                validation_results["file_descriptors_ok"] = False
            
        except ImportError:
            validation_results = {
                "sufficient_memory": None,
                "sufficient_cpu": None,
                "sufficient_disk": None,
                "file_descriptors_ok": None
            }
        
        return validation_results
    
    def print_system_status(self, target_count: int):
        """Print comprehensive system status and recommendations"""
        print("\n" + "="*60)
        print("🔧 SYSTEM CONFIGURATION ANALYSIS")
        print("="*60)
        
        # Current system status
        validation = self.validate_system_configuration()
        print("\n📊 CURRENT SYSTEM STATUS:")
        
        for check, result in validation.items():
            if result is None:
                status = "⚠️ Unable to check"
            elif result:
                status = "✅ OK"
            else:
                status = "❌ INSUFFICIENT"
            print(f"├── {check.replace('_', ' ').title()}: {status}")
        
        # Recommendations for target count
        recommendations = self.get_system_recommendations(target_count)
        print(f"\n🎯 RECOMMENDATIONS FOR {target_count:,} TARGETS:")
        print(f"├── CPU Cores: {recommendations['cpu_cores']}")
        print(f"├── Memory: {recommendations['memory_gb']} GB")
        print(f"├── Network: {recommendations['network_bandwidth']}")
        print(f"├── Storage: {recommendations['storage_capacity']} {recommendations['storage_type']}")
        
        print("\n🐧 OS CONFIGURATION:")
        for rec in recommendations['os_recommendations']:
            print(f"├── {rec}")
        
        print("\n⚙️ SYSTEM LIMITS:")
        for limit, value in recommendations['system_limits'].items():
            print(f"├── {limit}: {value}")
        
        print("\n🐳 DOCKER SETTINGS (if using containers):")
        for setting, value in recommendations['docker_settings'].items():
            print(f"├── --{setting}={value}")
        
        print("\n" + "="*60)


def load_optimized_config(target_count: int, config_dir: str = "./config"):
    """Convenience function to load optimized configuration"""
    loader = ConfigurationLoader(config_dir)
    
    try:
        large_scale_config = loader.load_large_scale_config()
        scanner_config = loader.create_scanner_config(target_count, large_scale_config)
        telegram_config = loader.create_telegram_config(large_scale_config)
        
        return {
            "scanner_config": scanner_config,
            "telegram_config": telegram_config,
            "system_recommendations": loader.get_system_recommendations(target_count)
        }
    except FileNotFoundError as e:
        print(f"❌ Configuration file not found: {e}")
        print("💡 Make sure large_scale_config.yaml exists in the config directory")
        return None


if __name__ == "__main__":
    # Test configuration loading
    loader = ConfigurationLoader()
    
    # Test with different target counts
    test_counts = [10000, 100000, 1000000, 10000000]
    
    for count in test_counts:
        print(f"\n{'='*20} {count:,} TARGETS {'='*20}")
        loader.print_system_status(count)
        
        # Test config creation
        try:
            config = load_optimized_config(count)
            if config:
                print(f"✅ Configuration loaded successfully for {count:,} targets")
                print(f"   Scanner mode: {config['scanner_config'].mode.value}")
                print(f"   Max concurrent: {config['scanner_config'].max_concurrent}")
                print(f"   Batch size: {config['scanner_config'].batch_size}")
        except Exception as e:
            print(f"❌ Failed to load config: {e}")