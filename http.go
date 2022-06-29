package trojan

import (
	stdLog "log"
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
		Handler:  h2c.NewHandler(h, h2s),
		ErrorLog: stdLog.New(stdLog.Writer(), "http", 0),
	}

	if err := s.Serve(ln); err != nil {
		log.Err(err).Msg("http server error")
	}
}
