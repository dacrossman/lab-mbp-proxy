package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	proxyPort      = "8888"
	socksPort      = "1080"
	homeWifiSSID   = "thewifi"
	sshCommand     = "ssh"
	sshArgs        = "-D"
	sshPortArg     = "1080"
	sshHost        = "sshj"
	internalSuffix = ".internal"
)

type ProxyServer struct {
	sshCmd       *exec.Cmd
	sshMutex     sync.Mutex
	socksDialer  proxy.Dialer
	tunnelActive bool
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		tunnelActive: false,
	}
}

// Check if connected to home WiFi
func (p *ProxyServer) isOnHomeNetwork() bool {
	// Use networksetup to get current WiFi network
	cmd := exec.Command("/usr/sbin/networksetup", "-getairportnetwork", "en0")
	output, err := cmd.Output()
	if err != nil {
		// Try en1 if en0 fails
		cmd = exec.Command("/usr/sbin/networksetup", "-getairportnetwork", "en1")
		output, err = cmd.Output()
		if err != nil {
			log.Printf("Failed to check WiFi: %v", err)
			return false
		}
	}

	// Output format: "Current Wi-Fi Network: SSID_NAME"
	line := strings.TrimSpace(string(output))
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			ssid := strings.TrimSpace(parts[1])
			log.Printf("Current WiFi: %s", ssid)
			return ssid == homeWifiSSID
		}
	}
	return false
}

// Check if domain should use SSH tunnel
func (p *ProxyServer) shouldUseTunnel(host string) bool {
	// Always direct if on home network
	if p.isOnHomeNetwork() {
		return false
	}

	// Check if it's an .internal domain
	return strings.HasSuffix(strings.ToLower(host), internalSuffix)
}

// Ensure SSH tunnel is running
func (p *ProxyServer) ensureTunnel() error {
	p.sshMutex.Lock()
	defer p.sshMutex.Unlock()

	if p.tunnelActive && p.sshCmd != nil && p.sshCmd.Process != nil {
		// Check if process is still running
		if err := p.sshCmd.Process.Signal(os.Signal(nil)); err == nil {
			return nil // Tunnel is active
		}
	}

	// Start SSH tunnel
	log.Println("Starting SSH tunnel...")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}
	sshConfigPath := homeDir + "/.ssh/config"
	p.sshCmd = exec.Command(sshCommand, "-F", sshConfigPath, sshArgs, sshPortArg, sshHost, "-N", "-o", "ServerAliveInterval=60", "-o", "ExitOnForwardFailure=yes")

	stderr, err := p.sshCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %v", err)
	}

	if err := p.sshCmd.Start(); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %v", err)
	}

	// Monitor stderr in background
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("SSH: %s", scanner.Text())
		}
	}()

	// Wait for tunnel to be ready
	time.Sleep(2 * time.Second)

	// Test SOCKS connection
	socksDialer, err := proxy.SOCKS5("tcp", "localhost:"+socksPort, nil, proxy.Direct)
	if err != nil {
		p.sshCmd.Process.Kill()
		return fmt.Errorf("failed to create SOCKS dialer: %v", err)
	}

	p.socksDialer = socksDialer
	p.tunnelActive = true
	log.Println("SSH tunnel established")

	// Monitor tunnel in background
	go func() {
		p.sshCmd.Wait()
		p.sshMutex.Lock()
		p.tunnelActive = false
		p.sshMutex.Unlock()
		log.Println("SSH tunnel closed")
	}()

	return nil
}

// Handle HTTP CONNECT for HTTPS
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	log.Printf("CONNECT request for %s", host)

	var targetConn net.Conn
	var err error

	hostOnly := strings.Split(r.Host, ":")[0]

	if p.shouldUseTunnel(hostOnly) {
		// Use SSH tunnel
		if err := p.ensureTunnel(); err != nil {
			log.Printf("Failed to establish tunnel: %v", err)
			http.Error(w, "Tunnel unavailable", http.StatusBadGateway)
			return
		}

		targetConn, err = p.socksDialer.Dial("tcp", host)
		if err != nil {
			log.Printf("Failed to dial through SOCKS: %v", err)
			http.Error(w, "Connection failed", http.StatusBadGateway)
			return
		}
		log.Printf("Routed %s through SSH tunnel", host)
	} else {
		// Direct connection
		targetConn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			log.Printf("Failed to dial directly: %v", err)
			http.Error(w, "Connection failed", http.StatusBadGateway)
			return
		}
		log.Printf("Direct connection to %s", host)
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Pipe data between client and target
	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

// Handle regular HTTP requests
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	hostOnly := strings.Split(host, ":")[0]
	log.Printf("HTTP request for %s", r.URL.String())

	var transport *http.Transport

	if p.shouldUseTunnel(hostOnly) {
		// Use SSH tunnel
		if err := p.ensureTunnel(); err != nil {
			log.Printf("Failed to establish tunnel: %v", err)
			http.Error(w, "Tunnel unavailable", http.StatusBadGateway)
			return
		}

		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.socksDialer.Dial(network, addr)
			},
		}
		log.Printf("Routed %s through SSH tunnel", host)
	} else {
		// Direct connection
		transport = &http.Transport{}
		log.Printf("Direct connection to %s", host)
	}

	// Forward the request
	client := &http.Client{Transport: transport}

	// Remove hop-by-hop headers
	r.RequestURI = ""

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		http.Error(w, "Request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func (p *ProxyServer) Shutdown() {
	p.sshMutex.Lock()
	defer p.sshMutex.Unlock()

	if p.sshCmd != nil && p.sshCmd.Process != nil {
		log.Println("Shutting down SSH tunnel...")
		p.sshCmd.Process.Kill()
		p.tunnelActive = false
	}
}

func main() {
	server := NewProxyServer()
	defer server.Shutdown()

	handler := http.HandlerFunc(server.handleHTTP)

	addr := "127.0.0.1:" + proxyPort
	log.Printf("Starting proxy server on %s", addr)
	log.Printf("Home WiFi SSID: %s", homeWifiSSID)
	log.Printf("Tunneling *.internal domains through SSH")

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
