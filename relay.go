package trojan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// relay copies between left and right bidirectionally
func relay(left, right net.Conn) (received, sent int64, err error) {
	var rerr, serr error
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		received, rerr = io.Copy(left, right)
		left.SetReadDeadline(time.Now())
	}()

	sent, serr = io.Copy(right, left)
	right.SetReadDeadline(time.Now())

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
