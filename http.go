package trojan

import (
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/togls/trojan-go/log"
)

func HttpServer(cfg *Config, ln net.Listener) {
	h := http.FileServer(http.Dir(cfg.WebRoot))

	h2s := &http2.Server{}

	s := &http.Server{
		Handler: h2c.NewHandler(h, h2s),
	}

	go func() {
		if err := s.Serve(ln); err != nil {
			log.Error().Err(err).Msg("http server")
		}
	}()
}
