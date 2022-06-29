package trojan

import (
	"context"
	"crypto/tls"
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
			err := s.handleConn(ctx, conn)
			if err != nil {
				log.Err(err).
					Str("remote", conn.RemoteAddr().String()).
					Msg("handle conn failed")
			}
		}()
	}
}

func (s *Server) Other() net.Listener {
	return s.http
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) error {
	conn := newBufConn(c)

	err := conn.Auth(s.authenticator)
	if err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s.http.conn <- conn:
		case <-s.http.done:
			_ = conn.Close()
		}

		return fmt.Errorf("auth failed: %w", err)
	}
	defer conn.Close()

	switch conn.cmd {
	case CmdConnect:
		rc, err := net.Dial("tcp", conn.addr.String())
		if err != nil {
			return fmt.Errorf("dial target: %w", err)
		}
		defer rc.Close()

		rn, sn, err := relay(conn, rc)
		if err != nil {
			return fmt.Errorf("relay tcp, target=%s: %w", conn.addr, err)
		}

		log.Info().
			Str("remote", conn.RemoteAddr().String()).
			Str("target", conn.addr.String()).
			Int64("recv", rn).
			Int64("send", sn).
			Msg("relay success")

	case CmdUDPAssociate:
		// TODO: support udp
		fallthrough
	default:
		return fmt.Errorf("unknown cmd: %w", err)
	}

	return nil
}
