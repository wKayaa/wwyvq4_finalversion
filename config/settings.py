#!/usr/bin/env python3
"""
⚙️ F8S Configuration Management
Centralized configuration loading and validation

Author: wKayaa
Date: 2025-01-28
"""

import yaml
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class F8SConfig:
    """F8S Framework configuration"""
    # Core settings
    max_concurrent_targets: int = 100
    timeout_per_operation: int = 15
    retry_count: int = 3
    skip_on_fail: bool = True
    
    # Module settings
    scanner_enabled: bool = True
    exploiter_enabled: bool = True
    extractor_enabled: bool = True
    validator_enabled: bool = True
    persistence_enabled: bool = True
    
    # Integration settings
    telegram_enabled: bool = False
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    discord_enabled: bool = False
    discord_webhook: Optional[str] = None
    
    # Web interface settings
    web_enabled: bool = False
    web_port: int = 5000
    web_host: str = "0.0.0.0"
    
    # API settings
    api_enabled: bool = False
    api_port: int = 8080
    api_host: str = "0.0.0.0"
    
    # Output settings
    output_directory: str = "./results"
    export_format: str = "json"
    detailed_logs: bool = True
    
    # Security settings
    validate_ssl: bool = True
    user_agent: str = "Mozilla/5.0 (compatible; F8S-Framework/2.0)"
    
    # Advanced settings
    cleanup_on_exit: bool = True
    session_persistence: bool = True
    error_threshold: int = 10
    
    # Module-specific configurations
    scanner_config: Dict = field(default_factory=dict)
    exploiter_config: Dict = field(default_factory=dict)
    extractor_config: Dict = field(default_factory=dict)
    validator_config: Dict = field(default_factory=dict)
    persistence_config: Dict = field(default_factory=dict)


def load_config(config_path: str) -> F8SConfig:
    """Load configuration from YAML file with defaults"""
    config = F8SConfig()
    
    config_file = Path(config_path)
    
    # Create default config if it doesn't exist
    if not config_file.exists():
        print(f"⚙️ Creating default configuration: {config_path}")
        create_default_config(config_path)
        return config
    
    try:
        with open(config_file, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                config_data = yaml.safe_load(f)
            else:
                config_data = json.load(f)
        
        # Update config with loaded data
        if config_data:
            _update_config_from_dict(config, config_data)
        
        print(f"✅ Configuration loaded from: {config_path}")
        
    except Exception as e:
        print(f"⚠️ Error loading config, using defaults: {str(e)}")
    
    return config


def create_default_config(config_path: str):
    """Create default configuration file"""
    default_config = {
        "core": {
            "max_concurrent_targets": 100,
            "timeout_per_operation": 15,
            "retry_count": 3,
            "skip_on_fail": True
        },
        "modules": {
            "scanner": {
                "enabled": True,
                "ports": [6443, 8443, 443, 80, 8080, 8001, 8888],
                "timeout": 5,
                "user_agent": "Mozilla/5.0 (compatible; F8S-Scanner/2.0)"
            },
            "exploiter": {
                "enabled": True,
                "aggressive_mode": False,
                "stealth_mode": False,
                "exploit_timeout": 30
            },
            "extractor": {
                "enabled": True,
                "extract_secrets": True,
                "extract_tokens": True,
                "extract_certificates": True
            },
            "validator": {
                "enabled": True,
                "validate_aws": True,
                "validate_gcp": True,
                "validate_azure": True,
                "validate_sendgrid": True,
                "validate_smtp": True
            },
            "persistence": {
                "enabled": True,
                "backdoor_pods": False,
                "create_accounts": False,
                "steal_tokens": True
            }
        },
        "integrations": {
            "telegram": {
                "enabled": False,
                "token": None,
                "chat_id": None,
                "notify_start": True,
                "notify_completion": True,
                "notify_errors": True,
                "notify_findings": True
            },
            "discord": {
                "enabled": False,
                "webhook_url": None,
                "notify_findings": True
            }
        },
        "web_interface": {
            "enabled": False,
            "host": "0.0.0.0",
            "port": 5000,
            "debug": False
        },
        "api_server": {
            "enabled": False,
            "host": "0.0.0.0",
            "port": 8080,
            "enable_cors": True
        },
        "output": {
            "directory": "./results",
            "export_format": "json",
            "detailed_logs": True,
            "compress_results": False
        },
        "security": {
            "validate_ssl": True,
            "user_agent": "Mozilla/5.0 (compatible; F8S-Framework/2.0)",
            "max_redirects": 3,
            "verify_certificates": False
        },
        "advanced": {
            "cleanup_on_exit": True,
            "session_persistence": True,
            "error_threshold": 10,
            "memory_limit_mb": 1024,
            "log_level": "INFO"
        }
    }
    
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_file, 'w') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            yaml.dump(default_config, f, default_flow_style=False, indent=2)
        else:
            json.dump(default_config, f, indent=2)
    
    print(f"✅ Default configuration created: {config_path}")


def validate_config(config: F8SConfig) -> bool:
    """Validate configuration settings"""
    validation_errors = []
    
    # Validate core settings
    if config.max_concurrent_targets <= 0:
        validation_errors.append("max_concurrent_targets must be > 0")
    
    if config.timeout_per_operation <= 0:
        validation_errors.append("timeout_per_operation must be > 0")
    
    if config.retry_count < 0:
        validation_errors.append("retry_count must be >= 0")
    
    # Validate Telegram settings
    if config.telegram_enabled:
        if not config.telegram_token:
            validation_errors.append("telegram_token required when telegram_enabled is True")
    
    # Validate Discord settings
    if config.discord_enabled:
        if not config.discord_webhook:
            validation_errors.append("discord_webhook required when discord_enabled is True")
    
    # Validate ports
    if config.web_enabled:
        if not (1 <= config.web_port <= 65535):
            validation_errors.append("web_port must be between 1 and 65535")
    
    if config.api_enabled:
        if not (1 <= config.api_port <= 65535):
            validation_errors.append("api_port must be between 1 and 65535")
    
    # Validate output directory
    try:
        Path(config.output_directory).mkdir(parents=True, exist_ok=True)
    except Exception:
        validation_errors.append(f"Cannot create output directory: {config.output_directory}")
    
    # Print validation results
    if validation_errors:
        print("❌ Configuration validation errors:")
        for error in validation_errors:
            print(f"  - {error}")
        return False
    
    print("✅ Configuration validation passed")
    return True


def _update_config_from_dict(config: F8SConfig, config_data: Dict[str, Any]):
    """Update config object from dictionary"""
    
    # Core settings
    if "core" in config_data:
        core = config_data["core"]
        config.max_concurrent_targets = core.get("max_concurrent_targets", config.max_concurrent_targets)
        config.timeout_per_operation = core.get("timeout_per_operation", config.timeout_per_operation)
        config.retry_count = core.get("retry_count", config.retry_count)
        config.skip_on_fail = core.get("skip_on_fail", config.skip_on_fail)
    
    # Module settings
    if "modules" in config_data:
        modules = config_data["modules"]
        
        if "scanner" in modules:
            config.scanner_enabled = modules["scanner"].get("enabled", config.scanner_enabled)
            config.scanner_config = modules["scanner"]
        
        if "exploiter" in modules:
            config.exploiter_enabled = modules["exploiter"].get("enabled", config.exploiter_enabled)
            config.exploiter_config = modules["exploiter"]
        
        if "extractor" in modules:
            config.extractor_enabled = modules["extractor"].get("enabled", config.extractor_enabled)
            config.extractor_config = modules["extractor"]
        
        if "validator" in modules:
            config.validator_enabled = modules["validator"].get("enabled", config.validator_enabled)
            config.validator_config = modules["validator"]
        
        if "persistence" in modules:
            config.persistence_enabled = modules["persistence"].get("enabled", config.persistence_enabled)
            config.persistence_config = modules["persistence"]
    
    # Integration settings
    if "integrations" in config_data:
        integrations = config_data["integrations"]
        
        if "telegram" in integrations:
            telegram = integrations["telegram"]
            config.telegram_enabled = telegram.get("enabled", config.telegram_enabled)
            config.telegram_token = telegram.get("token", config.telegram_token)
            config.telegram_chat_id = telegram.get("chat_id", config.telegram_chat_id)
        
        if "discord" in integrations:
            discord = integrations["discord"]
            config.discord_enabled = discord.get("enabled", config.discord_enabled)
            config.discord_webhook = discord.get("webhook_url", config.discord_webhook)
    
    # Web interface settings
    if "web_interface" in config_data:
        web = config_data["web_interface"]
        config.web_enabled = web.get("enabled", config.web_enabled)
        config.web_port = web.get("port", config.web_port)
        config.web_host = web.get("host", config.web_host)
    
    # API settings
    if "api_server" in config_data:
        api = config_data["api_server"]
        config.api_enabled = api.get("enabled", config.api_enabled)
        config.api_port = api.get("port", config.api_port)
        config.api_host = api.get("host", config.api_host)
    
    # Output settings
    if "output" in config_data:
        output = config_data["output"]
        config.output_directory = output.get("directory", config.output_directory)
        config.export_format = output.get("export_format", config.export_format)
        config.detailed_logs = output.get("detailed_logs", config.detailed_logs)
    
    # Security settings
    if "security" in config_data:
        security = config_data["security"]
        config.validate_ssl = security.get("validate_ssl", config.validate_ssl)
        config.user_agent = security.get("user_agent", config.user_agent)
    
    # Advanced settings
    if "advanced" in config_data:
        advanced = config_data["advanced"]
        config.cleanup_on_exit = advanced.get("cleanup_on_exit", config.cleanup_on_exit)
        config.session_persistence = advanced.get("session_persistence", config.session_persistence)
        config.error_threshold = advanced.get("error_threshold", config.error_threshold)


def get_environment_overrides() -> Dict[str, Any]:
    """Get configuration overrides from environment variables"""
    overrides = {}
    
    # Core settings
    if os.getenv("F8S_MAX_CONCURRENT"):
        overrides["max_concurrent_targets"] = int(os.getenv("F8S_MAX_CONCURRENT"))
    
    if os.getenv("F8S_TIMEOUT"):
        overrides["timeout_per_operation"] = int(os.getenv("F8S_TIMEOUT"))
    
    # Integration settings
    if os.getenv("F8S_TELEGRAM_TOKEN"):
        overrides["telegram_enabled"] = True
        overrides["telegram_token"] = os.getenv("F8S_TELEGRAM_TOKEN")
    
    if os.getenv("F8S_TELEGRAM_CHAT"):
        overrides["telegram_chat_id"] = os.getenv("F8S_TELEGRAM_CHAT")
    
    if os.getenv("F8S_DISCORD_WEBHOOK"):
        overrides["discord_enabled"] = True
        overrides["discord_webhook"] = os.getenv("F8S_DISCORD_WEBHOOK")
    
    # Output settings
    if os.getenv("F8S_OUTPUT_DIR"):
        overrides["output_directory"] = os.getenv("F8S_OUTPUT_DIR")
    
    return overrides


def apply_environment_overrides(config: F8SConfig):
    """Apply environment variable overrides to config"""
    overrides = get_environment_overrides()
    
    for key, value in overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)
            print(f"🔧 Environment override: {key} = {value}")


def save_config(config: F8SConfig, config_path: str):
    """Save configuration to file"""
    config_dict = {
        "core": {
            "max_concurrent_targets": config.max_concurrent_targets,
            "timeout_per_operation": config.timeout_per_operation,
            "retry_count": config.retry_count,
            "skip_on_fail": config.skip_on_fail
        },
        "modules": {
            "scanner": config.scanner_config,
            "exploiter": config.exploiter_config,
            "extractor": config.extractor_config,
            "validator": config.validator_config,
            "persistence": config.persistence_config
        },
        "integrations": {
            "telegram": {
                "enabled": config.telegram_enabled,
                "token": config.telegram_token,
                "chat_id": config.telegram_chat_id
            },
            "discord": {
                "enabled": config.discord_enabled,
                "webhook_url": config.discord_webhook
            }
        },
        "web_interface": {
            "enabled": config.web_enabled,
            "host": config.web_host,
            "port": config.web_port
        },
        "api_server": {
            "enabled": config.api_enabled,
            "host": config.api_host,
            "port": config.api_port
        },
        "output": {
            "directory": config.output_directory,
            "export_format": config.export_format,
            "detailed_logs": config.detailed_logs
        },
        "security": {
            "validate_ssl": config.validate_ssl,
            "user_agent": config.user_agent
        },
        "advanced": {
            "cleanup_on_exit": config.cleanup_on_exit,
            "session_persistence": config.session_persistence,
            "error_threshold": config.error_threshold
        }
    }
    
    config_file = Path(config_path)
    
    with open(config_file, 'w') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        else:
            json.dump(config_dict, f, indent=2)
    
    print(f"✅ Configuration saved to: {config_path}")