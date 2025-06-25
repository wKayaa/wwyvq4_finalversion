#!/bin/bash
# 🚀 Turbo Scanner Setup and Launch Script
# Configures and launches the optimized K8s scanner for 6-hour completion

set -e

echo "🚀 K8s Turbo Scanner - Setup & Launch"
echo "====================================="
echo ""

# Check if targets file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <targets_file> [output_dir]"
    echo ""
    echo "Examples:"
    echo "  $0 targets.txt"
    echo "  $0 mega_uhq_comprehensive.txt ./turbo_results"
    echo "  $0 targets_massive_optimized.txt ./6h_scan_results"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="${2:-./turbo_results_$(date +%Y%m%d_%H%M%S)}"

# Validate targets file exists
if [ ! -f "$TARGETS_FILE" ]; then
    echo "❌ Error: Targets file '$TARGETS_FILE' not found!"
    exit 1
fi

# Count targets
TARGET_COUNT=$(wc -l < "$TARGETS_FILE" 2>/dev/null || echo "0")
echo "🎯 Target Analysis:"
echo "   📁 File: $TARGETS_FILE"
echo "   📊 Count: $TARGET_COUNT targets"
echo "   📂 Output: $OUTPUT_DIR"
echo ""

# Calculate ETA
if [ "$TARGET_COUNT" -gt 0 ]; then
    ETA_HOURS=$(echo "scale=1; $TARGET_COUNT / 28 / 60" | bc -l 2>/dev/null || echo "~$(($TARGET_COUNT / 1680))")
    echo "⏰ Estimated completion time: ${ETA_HOURS} hours (at 28 IPs/min)"
    
    if [ "$TARGET_COUNT" -eq 9999 ]; then
        echo "🎯 Perfect! This is optimized for 9999 targets → ~6 hour completion"
    elif [ "$TARGET_COUNT" -gt 9999 ]; then
        echo "⚠️  Large target set detected. Consider splitting for optimal performance."
    fi
    echo ""
fi

# Performance configuration display
echo "🚀 TURBO MODE CONFIGURATION:"
echo "   ⚡ Concurrency: 5000 workers"  
echo "   ⏱️  Timeout: 3 seconds per request"
echo "   🔗 Connections: 5000 total, 1000 per host"
echo "   🎯 Ports: [6443, 8443, 10250] (critical K8s only)"
echo "   💾 Checkpoints: Every 500 IPs"
echo "   🚫 Validation: Disabled for maximum speed"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "📁 Created output directory: $OUTPUT_DIR"

# Check for Python dependencies (best effort)
echo "🔍 Checking dependencies..."
python3 -c "import asyncio; print('✅ asyncio available')" 2>/dev/null || echo "⚠️  asyncio check failed"

# Launch options
echo ""
echo "🚀 Launch Options:"
echo "1. Turbo Scanner (Recommended)"
echo "2. Manual K8s Scanner Ultimate"
echo "3. Show command only"
echo ""
read -p "Select option [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "🚀 Launching Turbo Scanner..."
        echo "Command: python3 turbo_scanner.py '$TARGETS_FILE' '$OUTPUT_DIR'"
        echo ""
        python3 turbo_scanner.py "$TARGETS_FILE" "$OUTPUT_DIR"
        ;;
    2)
        echo ""
        echo "🚀 Launching K8s Scanner Ultimate in Turbo Mode..."
        echo "Command: python3 k8s_scanner_ultimate.py --targets '$TARGETS_FILE' --mode turbo --output '$OUTPUT_DIR'"
        echo ""
        python3 k8s_scanner_ultimate.py --targets "$TARGETS_FILE" --mode turbo --output "$OUTPUT_DIR"
        ;;
    3)
        echo ""
        echo "📋 Commands to run manually:"
        echo ""
        echo "Turbo Scanner:"
        echo "python3 turbo_scanner.py '$TARGETS_FILE' '$OUTPUT_DIR'"
        echo ""
        echo "K8s Scanner Ultimate:"
        echo "python3 k8s_scanner_ultimate.py --targets '$TARGETS_FILE' --mode turbo --output '$OUTPUT_DIR'"
        echo ""
        ;;
    *)
        echo "❌ Invalid option. Exiting."
        exit 1
        ;;
esac

echo ""
echo "✅ Setup complete!"
echo "📊 Monitor progress in the scanner output"
echo "📁 Results will be saved to: $OUTPUT_DIR"