package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/togls/trojan-go/log"
)

type Server struct {
	ln   net.Listener
	http *listner

	authenticator Authenticator
}

func NewServer(addr string, tlsConfig *tls.Config, auth Authenticator) (*Server, error) {

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve tcp addr: %w", err)
	}

	tcpLn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for tcp: %w", err)
	}

	tlsLn := tls.NewListener(tcpLn, tlsConfig)

	httpLn := &listner{
		Listener: tlsLn,

		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
	}

	return &Server{
		ln:   tlsLn,
		http: httpLn,

		authenticator: auth,
	}, nil
}

func (s *Server) Serve(ctx context.Context) {
	log.Info().Msg("server started")

	for {
		select {
		case <-ctx.Done():
			s.http.Close()
			return
		default:
		}

		conn, err := s.ln.Accept()
		if err != nil {
			continue
		}

		go func() {
			err := s.handleConn(conn)
			if err != nil {
				log.Err(err).Msg("handle conn err")
			}
		}()
	}
}

func (s *Server) Other() net.Listener {
	return s.http
}

var ErrAuthFailed = errors.New("err auth failed")

func (s *Server) handleConn(c net.Conn) error {
	conn := newBufConn(c)

	err := conn.Auth(s.authenticator)
	if err != nil {
		select {
		case s.http.conn <- conn:
		case <-s.http.done:
			_ = conn.Close()
		}

		return ErrAuthFailed
	}
	defer conn.Close()

	switch conn.cmd {
	case CmdConnect:
		rc, err := net.Dial("tcp", conn.addr.String())
		if err != nil {
			log.Err(err).Msg("dial target err")
			return nil
		}
		defer rc.Close()

		err = relay(conn, rc)
		if err != nil {
			log.Err(err).Msg("relay err")
			return err
		}
	case CmdUDPAssociate:
		// TODO: support udp
		fallthrough
	default:
		log.Err(err).Msg("unknown cmd")
	}

	return nil
}
