// Package rs is the minimal Resource Server used by the demo.
//
// In gateway mode (what this demo uses), Keycloak validates the agent+jwt,
// runs constraint checks, and then proxies the request to this server. The
// server simply executes the business logic and returns a JSON body
// wrapped in a `data` field (per the spec's §5.11 sync response shape).
//
// A production resource server running in **direct mode** would also
// validate the agent JWT itself — either by calling Keycloak's
// /agent/introspect or by checking signature + aud locally against the
// agent's registered public key. For this mini demo we rely on gateway
// mode so the resource server has nothing to auth.
package rs

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

// CapabilityHandler turns parsed arguments into a JSON-serializable data
// object. The server wraps the result in {"data": <handler output>}.
type CapabilityHandler func(args map[string]any) map[string]any

// ResourceServer is a running HTTP server keyed by path → handler.
type ResourceServer struct {
	Server   *http.Server
	Listener net.Listener
	Port     int
}

// StartOn binds 0.0.0.0:port and begins serving; returns once the listener
// is accepting. Port 0 picks a random free port — handy for tests.
func StartOn(port int, handlers map[string]CapabilityHandler) (*ResourceServer, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handle(w, r, handlers)
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	boundPort := ln.Addr().(*net.TCPAddr).Port

	srv := &http.Server{Handler: mux}
	log.Printf("[resource-server] listening on :%d", boundPort)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[resource-server] serve error: %v", err)
		}
	}()
	return &ResourceServer{Server: srv, Listener: ln, Port: boundPort}, nil
}

// Close stops the server.
func (s *ResourceServer) Close() error {
	return s.Server.Close()
}

// URLFor builds the capability URL Keycloak (and the rest of the compose
// network) uses to reach this server.
func (s *ResourceServer) URLFor(path, serviceHost string) string {
	if serviceHost == "" {
		serviceHost = "resource-server"
	}
	return fmt.Sprintf("http://%s:%d%s", serviceHost, s.Port, path)
}

func handle(w http.ResponseWriter, r *http.Request, handlers map[string]CapabilityHandler) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	handler, ok := handlers[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "not_found",
			"path":  r.URL.Path,
		})
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	var parsed map[string]any
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	}
	args, _ := parsed["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	argsJSON, _ := json.Marshal(args)
	log.Printf("[resource-server] %s  args=%s", r.URL.Path, string(argsJSON))

	data := handler(args)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}
