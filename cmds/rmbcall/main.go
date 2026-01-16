package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	substrate "github.com/threefoldtech/tfchain/clients/tfchain-client-go"
	gridproxy "github.com/threefoldtech/tfgrid-sdk-go/grid-proxy/pkg/client"
	"github.com/threefoldtech/tfgrid-sdk-go/rmb-sdk-go/peer"
)

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
	// READ CONFIG

	mnemonic := os.Getenv("MNE")
	network := os.Getenv("NET")

	var nodeID uint
	var twinID uint
	var cmd string
	var payload string
	flag.UintVar(&nodeID, "node", 0, "node id (mutually exclusive with -twin)")
	flag.UintVar(&twinID, "twin", 0, "twin id (mutually exclusive with -node)")
	flag.StringVar(&cmd, "cmd", "", "command")
	flag.StringVar(&payload, "payload", "{}", "json payload (e.g. '{\"name\":\"omar\"}')")
	flag.Parse()

	if network == "" || mnemonic == "" {
		return errors.New("missing NET/MNE envvars")
	}
	if (nodeID == 0 && twinID == 0) || (nodeID != 0 && twinID != 0) {
		return errors.New("provide exactly one of -node or -twin")
	}
	if cmd == "" {
		return errors.New("missing -cmd")
	}

	// Grid Calls

	chainURL, relayURL, proxyURL, err := urlsFor(network)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if twinID == 0 {
		tid, err := twinIDFromNodeID(ctx, proxyURL, uint64(nodeID))
		if err != nil {
			return err
		}
		twinID = uint(tid)
	}

	man := substrate.NewManager(chainURL)
	rmb, err := peer.NewRpcClient(ctx, mnemonic, man, peer.WithRelay(relayURL), peer.WithSession("tfdbgr"))
	if err != nil {
		return err
	}

	var res any
	if err := rmb.Call(ctx, uint32(twinID), cmd, json.RawMessage(payload), &res); err != nil {
		return err
	}

	output, err := Jsonify(res)
	if err != nil {
		return err
	}

	fmt.Println(output)
	return nil
}

func Jsonify(data any) (string, error) {
	pres, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pres), nil
}

func urlsFor(network string) (chainURL, relayURL, proxyURL string, err error) {
	urlMap := map[string]string{
		"dev":  "dev.",
		"qa":   "qa.",
		"test": "test.",
		"main": "",
	}

	str, ok := urlMap[network]
	if !ok {
		return "", "", "", fmt.Errorf("invalid NET %q (expected dev|qa|test|main)", network)
	}

	return fmt.Sprintf("wss://tfchain.%sgrid.tf/", str),
		fmt.Sprintf("wss://relay.%sgrid.tf", str),
		fmt.Sprintf("https://gridproxy.%sgrid.tf", str),
		nil
}

func twinIDFromNodeID(ctx context.Context, proxyURL string, nodeID uint64) (uint32, error) {
	c := gridproxy.NewClient(proxyURL)
	node, err := c.Node(ctx, uint32(nodeID))
	if err != nil {
		return 0, fmt.Errorf("gridproxy query failed: %w", err)
	}

	return uint32(node.TwinID), nil
}
