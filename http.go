package trojan

import (
	stdLog "log"
	"net"
	"net/http"

	"github.com/togls/trojan-go/log"
)

func HttpServer(cfg *Config, ln net.Listener) {
	h := http.FileServer(http.Dir(cfg.WebRoot))

	s := &http.Server{
		Handler:  h,
		ErrorLog: stdLog.New(stdLog.Writer(), "http", 0),
	}

	if err := s.Serve(ln); err != nil {
		log.Err(err).Msg("http server error")
	}
}
