#!/bin/bash
# Generate Rust models from 3GPP OpenAPI specifications
#
# Prerequisites:
#   - openapi-generator-cli (npm install @openapitools/openapi-generator-cli -g)
#   - 3GPP OpenAPI specs in specs/ directory
#
# Usage:
#   ./generate_models.sh [interface]
#   ./generate_models.sh        # Generate all
#   ./generate_models.sh nnrf   # Generate only NRF models

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPECS_DIR="${SCRIPT_DIR}/specs"
OUTPUT_DIR="${SCRIPT_DIR}/../src/models/generated"
CONFIG_FILE="${SCRIPT_DIR}/openapi-generator-config.yaml"

# 3GPP API specifications to generate
declare -A SPECS=(
    ["nnrf_nfm"]="TS29510_Nnrf_NFManagement.yaml"
    ["nnrf_disc"]="TS29510_Nnrf_NFDiscovery.yaml"
    ["nnrf_token"]="TS29510_Nnrf_AccessToken.yaml"
    ["namf_comm"]="TS29518_Namf_Communication.yaml"
    ["namf_evts"]="TS29518_Namf_EventExposure.yaml"
    ["namf_loc"]="TS29518_Namf_Location.yaml"
    ["nsmf_pdusession"]="TS29502_Nsmf_PDUSession.yaml"
    ["nsmf_evts"]="TS29508_Nsmf_EventExposure.yaml"
    ["nudm_sdm"]="TS29503_Nudm_SDM.yaml"
    ["nudm_uecm"]="TS29503_Nudm_UECM.yaml"
    ["nudm_ueau"]="TS29503_Nudm_UEAU.yaml"
    ["nudr_dr"]="TS29504_Nudr_DR.yaml"
    ["nausf_auth"]="TS29509_Nausf_UEAuthentication.yaml"
    ["npcf_am"]="TS29507_Npcf_AMPolicyControl.yaml"
    ["npcf_sm"]="TS29512_Npcf_SMPolicyControl.yaml"
    ["npcf_ue"]="TS29525_Npcf_UEPolicyControl.yaml"
    ["nnssf_ns"]="TS29531_Nnssf_NSSelection.yaml"
    ["nbsf_mgmt"]="TS29521_Nbsf_Management.yaml"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    if ! command -v openapi-generator &> /dev/null; then
        log_error "openapi-generator not found. Install with:"
        echo "  npm install @openapitools/openapi-generator-cli -g"
        echo "  # or"
        echo "  brew install openapi-generator"
        exit 1
    fi

    if [ ! -d "$SPECS_DIR" ]; then
        log_warn "Specs directory not found. Creating..."
        mkdir -p "$SPECS_DIR"
        log_info "Download 3GPP OpenAPI specs to: $SPECS_DIR"
        log_info "Available from: https://www.3gpp.org/ftp/Specs/archive/OpenAPI/"
        log_info "Or use: https://github.com/jdegre/5GC_APIs"
        exit 1
    fi
}

# Download 3GPP specs if not present
download_specs() {
    local RELEASE="Rel-17"
    local BASE_URL="https://raw.githubusercontent.com/jdegre/5GC_APIs/main"

    log_info "Downloading 3GPP OpenAPI specs ($RELEASE)..."

    for key in "${!SPECS[@]}"; do
        local spec_file="${SPECS[$key]}"
        local target_path="${SPECS_DIR}/${spec_file}"

        if [ ! -f "$target_path" ]; then
            log_info "Downloading $spec_file..."
            curl -sL "${BASE_URL}/${spec_file}" -o "$target_path" || {
                log_warn "Failed to download $spec_file"
            }
        else
            log_info "Spec exists: $spec_file"
        fi
    done
}

# Generate models for a single interface
generate_interface() {
    local interface=$1
    local spec_file="${SPECS[$interface]}"

    if [ -z "$spec_file" ]; then
        log_error "Unknown interface: $interface"
        echo "Available interfaces: ${!SPECS[*]}"
        exit 1
    fi

    local spec_path="${SPECS_DIR}/${spec_file}"
    local output_path="${OUTPUT_DIR}/${interface}"

    if [ ! -f "$spec_path" ]; then
        log_error "Spec file not found: $spec_path"
        log_info "Run './generate_models.sh --download' to fetch specs"
        exit 1
    fi

    log_info "Generating models for $interface from $spec_file..."

    mkdir -p "$output_path"

    openapi-generator generate \
        -i "$spec_path" \
        -g rust \
        -o "$output_path" \
        --additional-properties=packageName=ogs-sbi-${interface},library=reqwest,supportAsync=true \
        --skip-validate-spec \
        --global-property=models,modelDocs=false,modelTests=false \
        2>&1 | grep -v "^\[main\]" || true

    # Post-process: Move models to correct location
    if [ -d "${output_path}/src/models" ]; then
        log_info "Post-processing models..."
        # Add common derives and fix imports
        for f in "${output_path}/src/models"/*.rs; do
            if [ -f "$f" ]; then
                # Add bytes import for binary data
                sed -i.bak 's/Vec<u8>/bytes::Bytes/g' "$f" 2>/dev/null || true
                rm -f "${f}.bak"
            fi
        done
    fi

    log_info "Generated: $output_path"
}

# Generate all interfaces
generate_all() {
    log_info "Generating models for all interfaces..."

    mkdir -p "$OUTPUT_DIR"

    for interface in "${!SPECS[@]}"; do
        generate_interface "$interface"
    done

    # Generate mod.rs
    log_info "Generating mod.rs..."
    cat > "${OUTPUT_DIR}/mod.rs" << 'EOF'
//! Auto-generated OpenAPI models from 3GPP specifications
//!
//! These models are generated from 3GPP OpenAPI specs using openapi-generator.
//! Do not edit manually - regenerate with generate_models.sh

EOF

    for interface in "${!SPECS[@]}"; do
        echo "pub mod ${interface};" >> "${OUTPUT_DIR}/mod.rs"
    done

    log_info "Done! Generated models in: $OUTPUT_DIR"
}

# Main
main() {
    check_prerequisites

    case "${1:-}" in
        --download)
            download_specs
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [INTERFACE]"
            echo ""
            echo "Options:"
            echo "  --download    Download 3GPP OpenAPI specs"
            echo "  --help        Show this help"
            echo ""
            echo "Interfaces:"
            for key in "${!SPECS[@]}"; do
                echo "  $key"
            done
            ;;
        "")
            generate_all
            ;;
        *)
            generate_interface "$1"
            ;;
    esac
}

main "$@"
