package trojan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/togls/trojan-go/log"
)

// relay copies between left and right bidirectionally
func relay(left, right net.Conn) (received, sent int64, err error) {
	var rerr, serr error
	wait := 5 * time.Second
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		received, rerr = io.Copy(left, right)
		left.SetReadDeadline(time.Now().Add(wait))
	}()

	sent, serr = io.Copy(right, left)
	right.SetReadDeadline(time.Now().Add(wait))

	wg.Wait()

	if serr != nil && !errors.Is(serr, os.ErrDeadlineExceeded) {
		err = fmt.Errorf("left->right: %w", serr)
		return
	}

	if rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded) {
		err = fmt.Errorf("right->left: %w", rerr)
		return
	}

	return
}

func relayUDP(left, right net.PacketConn) error {
	var received, sent int64
	var rerr, serr error

	go func() {
		// received, rerr = io.Copy(right, left)
		right.SetReadDeadline(time.Now())
	}()

	// sent, serr = io.Copy(left, right)
	left.SetReadDeadline(time.Now())

	if rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded) {
		return fmt.Errorf("relay left->right err %w", rerr)
	}

	if serr != nil && !errors.Is(serr, os.ErrDeadlineExceeded) {
		return fmt.Errorf("relay right->left err %w", serr)
	}

	log.Info().
		Int64("received", received).
		Int64("sent", sent).
		Msg("relay success")

	return nil
}
