#!/bin/bash

set -e

echo "Installing MBP Proxy Service..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please do not run as root/sudo. The script will ask for sudo when needed."
    exit 1
fi

# Build the binary
echo "Building mbp-proxy..."
go build -o mbp-proxy main.go

# Create necessary directories
echo "Creating directories..."
sudo mkdir -p /usr/local/var/log
sudo mkdir -p /usr/local/var/mbp-proxy
sudo chown $(whoami) /usr/local/var/log
sudo chown $(whoami) /usr/local/var/mbp-proxy

# Install binary
echo "Installing binary to /usr/local/bin/mbp-proxy..."
sudo cp mbp-proxy /usr/local/bin/mbp-proxy
sudo chmod +x /usr/local/bin/mbp-proxy

# Install launchd plist
echo "Installing launchd service..."
mkdir -p ~/Library/LaunchAgents
cp com.lab.mbp-proxy.plist ~/Library/LaunchAgents/com.lab.mbp-proxy.plist

# Unload if already running
if launchctl list | grep -q com.lab.mbp-proxy; then
    echo "Stopping existing service..."
    launchctl unload ~/Library/LaunchAgents/com.lab.mbp-proxy.plist 2>/dev/null || true
fi

# Load the service
echo "Starting service..."
launchctl load ~/Library/LaunchAgents/com.lab.mbp-proxy.plist

echo ""
echo "Installation complete!"
echo ""
echo "Service is now running on localhost:8888"
echo ""
echo "To configure Safari:"
echo "1. Open Safari → Settings → Advanced"
echo "2. Click 'Change Settings...' next to Proxies"
echo "3. Check 'Web Proxy (HTTP)' and set to 127.0.0.1:8888"
echo "4. Check 'Secure Web Proxy (HTTPS)' and set to 127.0.0.1:8888"
echo "5. Click OK and Apply"
echo ""
echo "Logs available at:"
echo "  /usr/local/var/log/mbp-proxy.log"
echo "  /usr/local/var/log/mbp-proxy.error.log"
echo ""
echo "To uninstall:"
echo "  launchctl unload ~/Library/LaunchAgents/com.lab.mbp-proxy.plist"
echo "  rm ~/Library/LaunchAgents/com.lab.mbp-proxy.plist"
echo "  sudo rm /usr/local/bin/mbp-proxy"
