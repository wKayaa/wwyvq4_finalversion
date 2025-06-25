#!/bin/bash
# 🚀 WWYVQ Large Scale Setup Script
# Author: wKayaa
# Date: 2025-01-17
#
# This script configures the system for optimal large-scale operations (16M+ targets)

set -e

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    🚀 WWYVQ LARGE SCALE SETUP 🚀                            ║"
echo "║                                                                              ║"
echo "║  Configuring system for 16+ million target processing                       ║"
echo "║                                                                              ║"
echo "║                              Author: wKayaa                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some optimizations require root privileges."
        IS_ROOT=true
    else
        print_info "Running as non-root user. Some system optimizations may be skipped."
        IS_ROOT=false
    fi
}

# Detect system information
detect_system() {
    print_info "Detecting system information..."
    
    OS=$(uname -s)
    ARCH=$(uname -m)
    
    if [[ "$OS" == "Linux" ]]; then
        if command -v lsb_release &> /dev/null; then
            DISTRO=$(lsb_release -si)
            VERSION=$(lsb_release -sr)
        elif [[ -f /etc/os-release ]]; then
            source /etc/os-release
            DISTRO=$NAME
            VERSION=$VERSION_ID
        else
            DISTRO="Unknown"
            VERSION="Unknown"
        fi
    else
        print_error "Unsupported operating system: $OS"
        exit 1
    fi
    
    print_success "System detected: $DISTRO $VERSION ($ARCH)"
}

# Check system resources
check_system_resources() {
    print_info "Checking system resources..."
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    print_info "CPU Cores: $CPU_CORES"
    
    if [[ $CPU_CORES -lt 8 ]]; then
        print_warning "Recommended: 8+ CPU cores for optimal performance"
    elif [[ $CPU_CORES -ge 16 ]]; then
        print_success "CPU cores sufficient for large scale operations"
    else
        print_success "CPU cores adequate for medium scale operations"
    fi
    
    # Check memory
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    print_info "Memory: ${MEMORY_GB}GB"
    
    if [[ $MEMORY_GB -lt 16 ]]; then
        print_warning "Recommended: 16GB+ RAM for large scale operations"
    elif [[ $MEMORY_GB -ge 32 ]]; then
        print_success "Memory sufficient for ultra large scale operations"
    else
        print_success "Memory adequate for large scale operations"
    fi
    
    # Check disk space
    DISK_SPACE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    print_info "Available disk space: ${DISK_SPACE}GB"
    
    if [[ $DISK_SPACE -lt 50 ]]; then
        print_warning "Recommended: 50GB+ free disk space"
    else
        print_success "Disk space sufficient"
    fi
}

# Install required packages
install_dependencies() {
    print_info "Installing required dependencies..."
    
    if [[ "$DISTRO" == *"Ubuntu"* ]] || [[ "$DISTRO" == *"Debian"* ]]; then
        if [[ "$IS_ROOT" == true ]]; then
            apt-get update
            apt-get install -y python3 python3-pip python3-venv htop iotop net-tools
            print_success "Dependencies installed via apt"
        else
            print_warning "Skipping system package installation (requires root)"
        fi
    elif [[ "$DISTRO" == *"CentOS"* ]] || [[ "$DISTRO" == *"Red Hat"* ]]; then
        if [[ "$IS_ROOT" == true ]]; then
            yum update -y
            yum install -y python3 python3-pip htop iotop net-tools
            print_success "Dependencies installed via yum"
        else
            print_warning "Skipping system package installation (requires root)"
        fi
    else
        print_warning "Unknown distribution. Please install Python3, pip, and monitoring tools manually."
    fi
}

# Install Python dependencies
install_python_dependencies() {
    print_info "Installing Python dependencies..."
    
    # Check if virtual environment should be used
    if [[ -n "$VIRTUAL_ENV" ]]; then
        print_info "Using existing virtual environment: $VIRTUAL_ENV"
    else
        print_info "Creating virtual environment..."
        python3 -m venv wwyvq_env
        source wwyvq_env/bin/activate
        print_success "Virtual environment created and activated"
    fi
    
    # Install requirements
    if [[ -f "requirements_ultimate.txt" ]]; then
        pip install -r requirements_ultimate.txt
        print_success "Python dependencies installed from requirements_ultimate.txt"
    else
        print_info "Installing core dependencies..."
        pip install aiohttp asyncio-mqtt pyyaml psutil rich questionary
        print_success "Core Python dependencies installed"
    fi
}

# Configure system limits
configure_system_limits() {
    print_info "Configuring system limits for large scale operations..."
    
    if [[ "$IS_ROOT" == true ]]; then
        # File descriptor limits
        echo "* soft nofile 1000000" >> /etc/security/limits.conf
        echo "* hard nofile 1000000" >> /etc/security/limits.conf
        
        # Process limits
        echo "* soft nproc 32768" >> /etc/security/limits.conf
        echo "* hard nproc 32768" >> /etc/security/limits.conf
        
        # Network optimizations
        cat >> /etc/sysctl.conf << EOF

# WWYVQ Large Scale Network Optimizations
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# Memory optimizations
vm.max_map_count = 262144
vm.swappiness = 1
EOF
        
        # Apply sysctl changes
        sysctl -p
        
        print_success "System limits configured for large scale operations"
    else
        print_warning "Skipping system limits configuration (requires root)"
        print_info "To configure manually as root:"
        print_info "  - Set file descriptor limits in /etc/security/limits.conf"
        print_info "  - Configure network parameters in /etc/sysctl.conf"
    fi
}

# Create optimized configuration
create_configuration() {
    print_info "Creating optimized configuration files..."
    
    # Create config directory
    mkdir -p config
    
    # Check if large_scale_config.yaml already exists
    if [[ -f "config/large_scale_config.yaml" ]]; then
        print_info "Large scale configuration already exists"
    else
        print_warning "Large scale configuration not found. Please ensure large_scale_config.yaml is present."
    fi
    
    # Create Docker configuration for containerized deployments
    cat > docker-compose.large-scale.yml << EOF
version: '3.8'

services:
  wwyvq-large-scale:
    build: .
    container_name: wwyvq-large-scale
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 1000000
        hard: 1000000
      nproc:
        soft: 32768
        hard: 32768
    sysctls:
      - net.core.somaxconn=65535
      - net.ipv4.ip_local_port_range=1024 65535
    deploy:
      resources:
        limits:
          memory: 64G
          cpus: '32'
        reservations:
          memory: 16G
          cpus: '8'
    volumes:
      - ./results:/app/results
      - ./config:/app/config
      - ./sessions:/app/sessions
    network_mode: host
    environment:
      - WWYVQ_MODE=large_scale
      - WWYVQ_MAX_CONCURRENT=10000
      - WWYVQ_MEMORY_LIMIT=64G
EOF
    
    print_success "Docker configuration created: docker-compose.large-scale.yml"
}

# Setup monitoring
setup_monitoring() {
    print_info "Setting up monitoring for large scale operations..."
    
    # Create monitoring script
    cat > monitor_large_scale.sh << 'EOF'
#!/bin/bash
# WWYVQ Large Scale Monitoring Script

echo "🔍 WWYVQ Large Scale Monitoring"
echo "==============================="
echo "Timestamp: $(date)"
echo ""

# System resources
echo "📊 SYSTEM RESOURCES:"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')"
echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
echo ""

# Network connections
echo "🌐 NETWORK STATUS:"
echo "Active connections: $(ss -tan | wc -l)"
echo "TIME_WAIT connections: $(ss -tan | grep TIME_WAIT | wc -l)"
echo ""

# Process information
echo "🔧 PROCESS STATUS:"
if pgrep -f "wwyvq\|python.*k8s" > /dev/null; then
    echo "WWYVQ processes: $(pgrep -f "wwyvq\|python.*k8s" | wc -l)"
    echo "Memory usage: $(ps -eo pid,comm,%mem --sort=-%mem | head -5)"
else
    echo "No WWYVQ processes detected"
fi
echo ""

# File descriptors
echo "📁 FILE DESCRIPTORS:"
if pgrep -f "wwyvq\|python.*k8s" > /dev/null; then
    for pid in $(pgrep -f "wwyvq\|python.*k8s"); do
        fd_count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        echo "PID $pid: $fd_count file descriptors"
    done
else
    echo "No WWYVQ processes to monitor"
fi
EOF
    
    chmod +x monitor_large_scale.sh
    print_success "Monitoring script created: monitor_large_scale.sh"
}

# Create startup script
create_startup_script() {
    print_info "Creating optimized startup script..."
    
    cat > start_large_scale.sh << 'EOF'
#!/bin/bash
# WWYVQ Large Scale Startup Script

set -e

echo "🚀 Starting WWYVQ Large Scale Operations"
echo "========================================"

# Check if virtual environment exists
if [[ -d "wwyvq_env" ]]; then
    echo "📦 Activating virtual environment..."
    source wwyvq_env/bin/activate
fi

# Set optimal environment variables
export PYTHONOPTIMIZE=1
export PYTHONUNBUFFERED=1
export AIOHTTP_NO_EXTENSIONS=1

# Memory and performance optimizations
export MALLOC_ARENA_MAX=2
export MALLOC_MMAP_THRESHOLD_=131072
export MALLOC_TRIM_THRESHOLD_=131072

# Large scale specific settings
export WWYVQ_LARGE_SCALE=1
export WWYVQ_MAX_CONCURRENT=10000
export WWYVQ_BATCH_SIZE=50000
export WWYVQ_ENABLE_MONITORING=1

echo "⚙️ Environment configured for large scale operations"
echo "🎯 Max concurrent: $WWYVQ_MAX_CONCURRENT"
echo "📦 Batch size: $WWYVQ_BATCH_SIZE"
echo ""

# Start the application
echo "🚀 Starting WWYVQ Master Framework..."
if [[ -f "wwyvq_master_final.py" ]]; then
    python wwyvq_master_final.py --mode ultimate --threads 10000 "$@"
elif [[ -f "large_scale_demo.py" ]]; then
    echo "🧪 Running large scale demo..."
    python large_scale_demo.py
else
    echo "❌ WWYVQ application not found"
    exit 1
fi
EOF
    
    chmod +x start_large_scale.sh
    print_success "Startup script created: start_large_scale.sh"
}

# Validate configuration
validate_setup() {
    print_info "Validating large scale setup..."
    
    # Check Python installation
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python3 version: $PYTHON_VERSION"
    else
        print_error "Python3 not found"
        return 1
    fi
    
    # Check pip packages
    if python3 -c "import aiohttp" 2>/dev/null; then
        print_success "aiohttp package available"
    else
        print_warning "aiohttp package not found"
    fi
    
    # Check file descriptor limits
    SOFT_LIMIT=$(ulimit -Sn)
    HARD_LIMIT=$(ulimit -Hn)
    print_info "File descriptor limits: soft=$SOFT_LIMIT, hard=$HARD_LIMIT"
    
    if [[ $SOFT_LIMIT -ge 65536 ]]; then
        print_success "File descriptor limits sufficient"
    else
        print_warning "File descriptor limits may be insufficient for large scale"
    fi
    
    # Check configuration files
    if [[ -f "config/large_scale_config.yaml" ]]; then
        print_success "Large scale configuration found"
    else
        print_warning "Large scale configuration not found"
    fi
    
    print_success "Setup validation completed"
}

# Print usage instructions
print_usage() {
    echo ""
    echo "🎯 LARGE SCALE SETUP COMPLETED"
    echo "=============================="
    echo ""
    echo "📋 Next steps:"
    echo "1. Review the configuration in config/large_scale_config.yaml"
    echo "2. Adjust target files (targets_massive_optimized.txt)"
    echo "3. Configure Telegram credentials if needed"
    echo "4. Start monitoring: ./monitor_large_scale.sh"
    echo "5. Launch large scale operations: ./start_large_scale.sh"
    echo ""
    echo "🐳 For Docker deployment:"
    echo "   docker-compose -f docker-compose.large-scale.yml up"
    echo ""
    echo "📊 For testing optimizations:"
    echo "   python large_scale_demo.py"
    echo ""
    echo "💡 System recommendations for 16M+ targets:"
    echo "   - CPU: 32+ cores"
    echo "   - RAM: 64GB+"
    echo "   - Network: 10Gbps+"
    echo "   - Storage: 2TB+ NVMe SSD"
    echo ""
}

# Main execution
main() {
    check_root
    detect_system
    check_system_resources
    install_dependencies
    install_python_dependencies
    configure_system_limits
    create_configuration
    setup_monitoring
    create_startup_script
    validate_setup
    print_usage
}

# Run main function
main "$@"