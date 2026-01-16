package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	substrate "github.com/threefoldtech/tfchain/clients/tfchain-client-go"
	"github.com/threefoldtech/tfgrid-sdk-go/rmb-sdk-go/peer"
	"golang.org/x/crypto/ssh"
)

const (
	gridproxyURL = "https://gridproxy.dev.grid.tf"
	chainURL     = "wss://tfchain.dev.grid.tf/"
	relayURL     = "wss://relay.dev.grid.tf"
)

const (
	defaultMnemonic  = ""
	defaultSSHKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----`
)

type gridProxyNode struct {
	ID        string `json:"id"`
	NodeID    uint32 `json:"nodeId"`
	TwinID    uint32 `json:"twinId"`
	Resources struct {
		MRU uint64 `json:"mru"`
	} `json:"total_resources"`
	UsedResources struct {
		MRU uint64 `json:"mru"`
	} `json:"used_resources"`
}

type nodeReport struct {
	NodeID    uint32 `json:"node_id"`
	TwinID    uint32 `json:"twin_id"`
	PrivateIP string `json:"private_ip"`
	FromGrid  struct {
		TotalMRU uint64 `json:"total_mru"`
		UsedMRU  uint64 `json:"used_mru"`
	} `json:"from_gridproxy"`
	FromStats struct {
		TotalMRU uint64 `json:"total_mru"`
		UsedMRU  uint64 `json:"used_mru"`
	} `json:"from_statistics"`
	FromSSH struct {
		TotalBytes uint64 `json:"total_bytes"`
		UsedBytes  uint64 `json:"used_bytes"`
	} `json:"from_ssh_free_b"`
	Notes []string `json:"notes"`
}

func main() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().
		Timestamp().
		Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if err := run(); err != nil {
		log.Error().Err(err).Msg("failed")
		os.Exit(1)
	}
}

func run() error {
	const (
		timeoutSec    = 5
		workers       = 8
		ipOutFile     = "node_private_ips.txt"
		reportOutFile = "node_reports.jsonl"
	)

	mnemonic := defaultMnemonic
	if mnemonic == "" {
		return errors.New("missing defaultMnemonic")
	}
	sshKeyPEM := defaultSSHKeyPEM
	if sshKeyPEM == "" {
		return errors.New("missing defaultSSHKeyPEM")
	}

	// Step 1: get nodes from proxy
	nodes, err := getNodesFromProxy()
	if err != nil {
		return err
	}

	// RMB client
	man := substrate.NewManager(chainURL)
	rmbClient, err := peer.NewRpcClient(context.Background(), mnemonic, man, peer.WithRelay(relayURL), peer.WithSession("audit-nodes"))
	if err != nil {
		return err
	}

	// Output files
	ipMapFile, err := os.Create(filepath.Clean(ipOutFile))
	if err != nil {
		return err
	}
	defer ipMapFile.Close()
	reportFile, err := os.Create(filepath.Clean(reportOutFile))
	if err != nil {
		return err
	}
	defer reportFile.Close()

	type job struct{ n gridProxyNode }
	jobs := make(chan job)
	var wg sync.WaitGroup
	var ipMu sync.Mutex

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
			// Steps per node:
			// - RMB to get private IP
			// - Save mapping
			// - Proxy statistics
			// - SSH free -b
			rep := processNode(ctx, rmbClient, j.n, sshKeyPEM)
			cancel()

			// Write IP map line if present
			if rep.PrivateIP != "" {
				ipMu.Lock()
				_, _ = fmt.Fprintf(ipMapFile, "%d %s\n", rep.NodeID, rep.PrivateIP)
				ipMu.Unlock()
			}

			// Write report line
			b, _ := json.Marshal(rep)
			_, _ = fmt.Fprintf(reportFile, "%s\n", string(b))
		}
	}

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	// Enqueue jobs
	for _, n := range nodes {
		jobs <- job{n: n}
	}
	close(jobs)
	wg.Wait()

	log.Info().Int("nodes", len(nodes)).Msg("processed nodes")
	log.Info().Str("path", ipOutFile).Msg("ip map written")
	log.Info().Str("path", reportOutFile).Msg("reports written")
	return nil
}

func getNodesFromProxy() ([]gridProxyNode, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/nodes?healthy=true", gridproxyURL), nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gridproxy status: %s", res.Status)
	}
	var nodes []gridProxyNode
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func processNode(ctx context.Context, rmb *peer.RpcClient, n gridProxyNode, sshKeyPEM string) nodeReport {
	rep := nodeReport{NodeID: n.NodeID, TwinID: n.TwinID}
	rep.FromGrid.TotalMRU = n.Resources.MRU
	rep.FromGrid.UsedMRU = n.UsedResources.MRU

	// RMB: zos.network.interfaces
	privateIP, noteNI := fetchPrivateIP(ctx, rmb, n.TwinID)
	if noteNI != "" {
		rep.Notes = append(rep.Notes, noteNI)
	}
	rep.PrivateIP = privateIP

	// GridProxy: /nodes/{id}/statistics
	totalMRU, usedMRU, noteStats := fetchStatisticsFromGridproxy(ctx, n.NodeID)
	if noteStats != "" {
		rep.Notes = append(rep.Notes, noteStats)
	}
	rep.FromStats.TotalMRU = totalMRU
	rep.FromStats.UsedMRU = usedMRU

	// SSH: free -b
	if privateIP != "" {
		t, u, noteSSH := sshFreeB(ctx, privateIP, sshKeyPEM)
		if noteSSH != "" {
			rep.Notes = append(rep.Notes, noteSSH)
		}
		rep.FromSSH.TotalBytes = t
		rep.FromSSH.UsedBytes = u
	} else {
		rep.Notes = append(rep.Notes, "SSH skipped: missing creds or private IP")
	}

	return rep
}

func fetchPrivateIP(ctx context.Context, rmb *peer.RpcClient, twinID uint32) (string, string) {
	var res any
	if err := rmb.Call(ctx, twinID, "zos.network.interfaces", struct{}{}, &res); err != nil {
		return "", "interfaces call failed or timed out"
	}
	ip := extractPrivateIP(res)
	if ip == "" {
		return "", "no private 10.* IP found"
	}
	return ip, ""
}

func extractPrivateIP(res any) string {
	var findIn func(map[string]any) string
	var findInSlice func([]any) string
	findIn = func(m map[string]any) string {
		for k, v := range m {
			// key may hint it's an address
			if strings.Contains(strings.ToLower(k), "addr") || strings.Contains(strings.ToLower(k), "ip") {
				if s, ok := v.(string); ok {
					if isPrivate10IPv4(s) {
						return stripCIDR(s)
					}
				}
			}
			switch vv := v.(type) {
			case string:
				if isPrivate10IPv4(vv) {
					return stripCIDR(vv)
				}
			case map[string]any:
				if r := findIn(vv); r != "" {
					return r
				}
			case []any:
				if r := findInSlice(vv); r != "" {
					return r
				}
			}
		}
		return ""
	}
	findInSlice = func(arr []any) string {
		for _, it := range arr {
			switch vv := it.(type) {
			case string:
				if isPrivate10IPv4(vv) {
					return stripCIDR(vv)
				}
			case map[string]any:
				if r := findIn(vv); r != "" {
					return r
				}
			case []any:
				if r := findInSlice(vv); r != "" {
					return r
				}
			}
		}
		return ""
	}

	switch v := res.(type) {
	case map[string]any:
		return findIn(v)
	case []any:
		return findInSlice(v)
	default:
		return ""
	}
}

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

func isPrivate10IPv4(s string) bool {
	ip := stripCIDR(s)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return strings.HasPrefix(parsed.String(), "10.")
}

func fetchStatisticsFromGridproxy(ctx context.Context, nodeID uint32) (totalMRU uint64, usedMRU uint64, note string) {
	url := fmt.Sprintf("%s/nodes/%d/statistics", gridproxyURL, nodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, "statistics request build failed"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return 0, 0, "statistics request failed or timed out"
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, 0, "statistics non-200 response"
	}
	var body struct {
		Total struct {
			MRU uint64 `json:"mru"`
		} `json:"total"`
		Used struct {
			MRU uint64 `json:"mru"`
		} `json:"used"`
	}
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&body); err != nil {
		return 0, 0, "statistics decode failed"
	}
	return body.Total.MRU, body.Used.MRU, ""
}

// (legacy parser removed) findFirstNumberByKeys

// toFloat was used by the RMB statistics parser; no longer needed with GridProxy stats

func sshFreeB(ctx context.Context, host, keyPEM string) (total, used uint64, note string) {
	addr := net.JoinHostPort(host, "22")
	if keyPEM == "" {
		note = "no SSH key PEM provided"
		return
	}
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		note = "SSH key PEM parse failed"
		return
	}

	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if note == "" {
			note = "SSH dial failed"
		}
		return
	}
	defer conn.Close()
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		note = "SSH handshake failed"
		return
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		if note == "" {
			note = "SSH new session failed"
		}
		return
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		if note == "" {
			note = "SSH stdout pipe failed"
		}
		return
	}

	if err := session.Start("free -b"); err != nil {
		if note == "" {
			note = "SSH command start failed"
		}
		return
	}

	done := make(chan struct{})
	var outLines []string
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			outLines = append(outLines, scanner.Text())
		}
		close(done)
	}()

	select {
	case <-done:
		_ = session.Wait()
	case <-time.After(3 * time.Second):
		_ = session.Signal(ssh.SIGKILL)
		if note == "" {
			note = "SSH command timeout"
		}
		return
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		if note == "" {
			note = "context canceled"
		}
		return
	}

	// Parse free -b output: look for line starting with "Mem:"
	for _, line := range outLines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(fields[0]), "mem") {
			// Common format: Mem: total used free ...
			t, u := parseUint(fields[1]), parseUint(fields[2])
			total, used = t, u
			return
		}
	}
	if note == "" {
		note = "unable to parse free -b output"
	}
	return
}

func parseUint(s string) uint64 {
	// Remove any commas or non-digits
	s = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v*10 + uint64(s[i]-'0')
	}
	return v
}
