package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	substrate "github.com/threefoldtech/tfchain/clients/tfchain-client-go"
	"github.com/threefoldtech/tfgrid-sdk-go/rmb-sdk-go/peer"
)

const (
	chain = "wss://tfchain.dev.grid.tf/"
	relay = "wss://relay.dev.grid.tf"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	var dest uint
	var cmd string
	flag.UintVar(&dest, "dest", 0, "destination")
	flag.StringVar(&cmd, "cmd", "", "command")
	flag.Parse()

	mnemonic := os.Getenv("MNEMONIC")

	if dest == 0 || cmd == "" || mnemonic == "" {
		return errors.New("missing flag/envvar")
	}

	man := substrate.NewManager(chain)
	rmb, err := peer.NewRpcClient(context.Background(), mnemonic, man, peer.WithRelay(relay), peer.WithSession("debugging-tools")) // Todo: add twin id to session
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	payload := struct {
		Name string `json:"name"`
	}{
		Name: "iperf",
	}
	var res any
	if err := rmb.Call(ctx, uint32(dest), cmd, payload, &res); err != nil {
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
