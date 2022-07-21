package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/togls/trojan-go"
)

type flagSet struct {
	config  string
	keyLog  string
	log     string
	test    bool
	version bool
}

func main() {
	var fs flagSet
	flag.StringVar(&fs.config, "c", "", "specify config file")
	flag.StringVar(&fs.keyLog, "k", "", "specify keylog file location")
	flag.StringVar(&fs.log, "l", "", "specify log file location")
	flag.BoolVar(&fs.test, "t", false, "test config file")
	flag.BoolVar(&fs.version, "v", false, "print version")
	flag.Parse()

	if fs.version {
		fmt.Printf("trojan %s\n", trojan.Version)
		os.Exit(0)
	}

	if fs.config == "" {
		var err error
		fs.config, err = defaultConfigFile()
		if err != nil {
			log.Fatal(err)
		}
	}

	cfg, err := trojan.ParseConfig(fs.config)
	if err != nil {
		log.Fatal(err)
	}

	err = cfg.Validate()
	if err != nil {
		log.Fatal(err)
	}

	if fs.test {
		os.Exit(0)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	switch *cfg.Type {
	case trojan.RunTypeServer:
		addr := fmt.Sprintf("%s:%d", cfg.LocalAddr, cfg.LocalPort)

		tlsConfig, err := trojan.TlsConfig(ctx, cfg)
		if err != nil {
			log.Fatal(err)
		}

		s, err := trojan.NewServer(addr, tlsConfig, trojan.NewMemAuth(cfg.Password))
		if err != nil {
			log.Fatal(err)
		}

		trojan.HttpServer(cfg, s.Other())

		s.Serve(ctx)
	default:
		log.Fatal("unspported run type")
	}

	<-ctx.Done()
}

func defaultConfigFile() (string, error) {
	return "", errors.New("can not find config file")
}
