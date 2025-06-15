#!/bin/bash
# MTProxy entrypoint with Cloudflare WARP routing
# Simplified version - removed unnecessary Telegram IP routing

set -euo pipefail

#############################################
# Configuration Constants
#############################################
readonly TABLE_NAME="warp"
readonly TABLE_ID=51820
readonly WG_IF="wgcf"
readonly WG_CONFIG_FILE="${WG_CONFIG_FILE:-/etc/wireguard/wgcf.conf}"
readonly TLS_DOMAIN="${TLS_DOMAIN:-}"
readonly SECRET_FILE="${SECRET_FILE:-/data/secret.txt}"
readonly MTPROXY_PORT="${MTPROXY_PORT:-8888}"
readonly MTPROXY_HTTP_PORT="${MTPROXY_HTTP_PORT:-7432}"
readonly PROXY_USER="${PROXY_USER:-mtproxy}"

#############################################
# Logging Functions
#############################################
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

#############################################
# System Setup Functions
#############################################
setup_dns() {
    log_info "Configuring DNS servers..."
    cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF
    log_info "DNS configuration completed"
}

setup_tun_device() {
    log_info "Setting up TUN device..."
    mkdir -p /dev/net
    
    if [[ ! -c /dev/net/tun ]]; then
        mknod /dev/net/tun c 10 200
        log_info "Created TUN device"
    else
        log_info "TUN device already exists"
    fi
    
    chmod 600 /dev/net/tun
    log_info "TUN device setup completed"
}

setup_routing_table() {
    log_info "Setting up WARP routing table..."
    
    # Add custom routing table if not exists
    if ! grep -q "^${TABLE_ID}[[:space:]]${TABLE_NAME}$" /etc/iproute2/rt_tables; then
        echo "${TABLE_ID} ${TABLE_NAME}" >> /etc/iproute2/rt_tables
        log_info "Added routing table: ${TABLE_NAME} (${TABLE_ID})"
    fi
    
    # Add default route for WARP interface (will be added after WG starts)
    log_info "Routing table setup completed"
}

#############################################
# WireGuard Functions
#############################################
start_wireguard() {
    log_info "Starting WireGuard tunnel..."
    
    # Check if WireGuard config exists
    if [[ ! -f "$WG_CONFIG_FILE" ]]; then
        log_error "WireGuard configuration file '$WG_CONFIG_FILE' not found"
        log_error "Please set WG_CONFIG_FILE environment variable or mount the config file"
        return 1
    fi
    
    # Validate config file
    if ! grep -q "\[Interface\]" "$WG_CONFIG_FILE" || ! grep -q "\[Peer\]" "$WG_CONFIG_FILE"; then
        log_error "Invalid WireGuard configuration file: $WG_CONFIG_FILE"
        return 1
    fi
    
    # Start WireGuard using the config file
    if wg-quick up "$WG_CONFIG_FILE"; then
        log_info "WireGuard tunnel started successfully using $WG_CONFIG_FILE"
    else
        log_error "Failed to start WireGuard tunnel"
        return 1
    fi
    
    # Wait for interface to be ready
    sleep 3
    
    # Add default route for WARP table
    if ip route add default dev "${WG_IF}" table "${TABLE_NAME}" 2>/dev/null; then
        log_info "Added default route for ${WG_IF} in table ${TABLE_NAME}"
    else
        log_info "Default route already exists"
    fi
    
    # Verify interface is up
    if ip link show "$WG_IF" &>/dev/null; then
        log_info "WireGuard interface ${WG_IF} is up"
    else
        log_error "WireGuard interface ${WG_IF} is not up"
        return 1
    fi
    
    # Verify external IP
    log_info "Verifying external IP via WARP..."
    if external_ip=$(timeout 10 curl -sf https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -E "^ip=" | head -n1); then
        log_info "WARP connection verified: $external_ip"
    else
        log_warn "Failed to verify WARP connection, but continuing..."
    fi
}

#############################################
# Proxy Configuration Functions
#############################################
download_proxy_files() {
    log_info "Downloading proxy configuration files..."
    
    # Download proxy secret if not exists
    if [[ ! -f "proxy-secret" ]]; then
        log_info "Downloading proxy secret..."
        if timeout 30 curl -sf https://core.telegram.org/getProxySecret -o proxy-secret; then
            log_info "Proxy secret downloaded successfully"
        else
            log_error "Failed to download proxy secret"
            return 1
        fi
    else
        log_info "Proxy secret already exists"
    fi
    
    # Download proxy config if not exists or older than 1 day
    if [[ ! -f "proxy-multi.conf" ]] || [[ $(find proxy-multi.conf -mtime +1 2>/dev/null | wc -l) -gt 0 ]]; then
        log_info "Downloading proxy configuration..."
        if timeout 30 curl -sf https://core.telegram.org/getProxyConfig -o proxy-multi.conf; then
            log_info "Proxy configuration downloaded successfully"
        else
            log_error "Failed to download proxy configuration"
            return 1
        fi
    else
        log_info "Proxy configuration is up to date"
    fi
}

setup_secret() {
    log_info "Setting up proxy secret..."
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$SECRET_FILE")"
    
    # Generate secret if file doesn't exist or is empty
    if [[ ! -f "$SECRET_FILE" ]] || [[ ! -s "$SECRET_FILE" ]]; then
        log_info "Generating new proxy secret..."
        if head -c 16 /dev/urandom | xxd -plain > "$SECRET_FILE"; then
            log_info "New proxy secret generated"
        else
            log_error "Failed to generate proxy secret"
            return 1
        fi
    else
        log_info "Using existing proxy secret"
    fi
    
    # Read and validate secret
    if SECRET=$(cat "$SECRET_FILE" 2>/dev/null) && [[ -n "$SECRET" ]] && [[ ${#SECRET} -eq 32 ]]; then
        log_info "Proxy secret loaded successfully (length: ${#SECRET})"
    else
        log_error "Failed to read proxy secret or invalid secret format"
        return 1
    fi
}

#############################################
# MTProxy Functions
#############################################
start_mtproxy() {
    log_info "Starting MTProxy server..."
    
    # Validate required files
    local required_files=("./mtproto-proxy" "proxy-secret" "proxy-multi.conf")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
            log_error "Required file not found or empty: $file"
            return 1
        fi
    done
    
    # Make sure mtproto-proxy is executable
    chmod +x ./mtproto-proxy
    
    # Build command array
    local cmd=(
        "./mtproto-proxy"
        "-u" "$PROXY_USER"
        "-p" "$MTPROXY_PORT"
        "-H" "$MTPROXY_HTTP_PORT"
        "-S" "$SECRET"
    )

    if [[ -n "${TLS_DOMAIN:-}" ]]; then
      cmd+=("-D" "$TLS_DOMAIN")
    fi
    
    # Add proxy tag if specified
    if [[ -n "${PROXY_TAG:-}" ]]; then
        cmd+=("-P" "$PROXY_TAG")
        log_info "Using proxy tag: $PROXY_TAG"
    fi
    
    # Add remaining options
    cmd+=(
        "-R"  # Use random padding
        "--aes-pwd" "proxy-secret" "proxy-multi.conf"
        "-M" "1"  # Use single-process mode
    )
    
    log_info "Starting MTProxy with command: ${cmd[*]}"
    log_info "MTProxy will listen on ports: $MTPROXY_PORT (main), $MTPROXY_HTTP_PORT (HTTP)"
    log_info "TLS domain: $TLS_DOMAIN"
    log_info "Traffic will be routed through WARP tunnel for enhanced privacy"
    
    # Execute MTProxy
    exec "${cmd[@]}"
}

#############################################
# Cleanup Functions
#############################################
cleanup() {
    log_info "Cleaning up..."
    
    # Stop WireGuard if running
    if wg show "$WG_IF" &>/dev/null; then
        log_info "Stopping WireGuard..."
        wg-quick down "$WG_CONFIG_FILE" 2>/dev/null || true
    fi
    
    log_info "Cleanup completed"
}

# Set up signal handlers for graceful shutdown
trap cleanup EXIT INT TERM

#############################################
# Main Execution
#############################################
main() {
    log_info "Starting MTProxy with WARP routing..."
    log_info "Configuration: Table=${TABLE_NAME}, Interface=${WG_IF}, TLS=${TLS_DOMAIN}"
    log_info "WireGuard config: $WG_CONFIG_FILE"
    
    # Execute setup functions in order
    setup_dns
    setup_tun_device
    setup_routing_table
    start_wireguard          # Critical: Must succeed
    download_proxy_files     # Critical: Must succeed
    setup_secret            # Critical: Must succeed
    start_mtproxy          # Final step: Start the proxy
}

# Run main function with all arguments
main "$@"