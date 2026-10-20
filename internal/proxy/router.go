package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Router serves several environments on one port, each under /<name>/, so
// mcp-grafana uses GRAFANA_URL=http://<proxy>/<name>. Handlers must be built
// with the matching Prefix.
type Router struct {
	mu       sync.RWMutex
	handlers map[string]http.Handler
}

// Set replaces the environments the router serves.
func (rt *Router) Set(handlers map[string]http.Handler) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.handlers = handlers
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check before routing so a web page cannot even probe environment names.
	if status, msg := checkRequest(r); status != 0 {
		writeError(w, status, msg)
		return
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	rt.mu.RLock()
	h, ok := rt.handlers[name]
	rt.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf(
			"mcp-grafana-proxy has no environment %q: add it in the UI, and set GRAFANA_URL to http://<proxy>/<environment>", name))
		return
	}
	h.ServeHTTP(w, r)
}
