package api

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestStopForceClosesConnectionsAfterShutdownTimeout guards the restart race that
// surfaced as "unknown provider for model ...": when graceful shutdown gives up,
// the surviving keep-alive connections must be dropped instead of continuing to
// reach the handlers while the caller tears the model registry down.
func TestStopForceClosesConnectionsAfterShutdownTimeout(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	httpServer := &http.Server{Handler: mux}
	go func() { _ = httpServer.Serve(listener) }()

	conn, errDial := net.Dial("tcp", listener.Addr().String())
	if errDial != nil {
		t.Fatalf("dial: %v", errDial)
	}
	defer func() { _ = conn.Close() }()

	if _, errWrite := fmt.Fprint(conn, "GET /block HTTP/1.1\r\nHost: test\r\n\r\n"); errWrite != nil {
		t.Fatalf("write request: %v", errWrite)
	}

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never received the request")
	}

	s := &Server{server: httpServer}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// The in-flight request keeps the connection busy, so graceful shutdown times out.
	if errStop := s.Stop(ctx); errStop == nil {
		t.Fatal("expected Stop to report a shutdown timeout")
	}

	// Stop must have force-closed the connection; unblocking the handler afterwards
	// should not produce a response on the wire.
	close(release)
	if errDeadline := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); errDeadline != nil {
		t.Fatalf("set read deadline: %v", errDeadline)
	}
	if _, errRead := bufio.NewReader(conn).ReadString('\n'); errRead == nil {
		t.Fatal("connection survived the shutdown timeout and still served the request")
	}
}
