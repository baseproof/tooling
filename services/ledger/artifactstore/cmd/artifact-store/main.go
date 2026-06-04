/*
FILE PATH:

	artifactstore/cmd/artifact-store/main.go

DESCRIPTION:

	Phase 5 — the artifact-store service entrypoint. Serves the /v1/artifacts
	contract (baseproof#97) over an artifactstore.Store, so a ledger configured for
	service mode injects an SDK HTTPContentStore{baseURL} pointed here in place of
	the in-process *Store. Thin composition root: flags -> backend -> Store ->
	Server -> ListenAndServe. Imports only the module + stdlib (portable).
*/
package main

import (
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dir := flag.String("dir", "", "posix storage root (empty = in-memory, dev only)")
	restricted := flag.Bool("restricted", false, "RESTRICTED posture (deny anonymous fetch; resolve via the hook)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var backend artifactstore.Backend
	if *dir == "" {
		logger.Warn("artifact-store: in-memory backend (dev only; not durable)")
		backend = artifactstore.NewMemoryBackend()
	} else {
		b, err := artifactstore.NewPosixBackend(*dir)
		if err != nil {
			log.Fatalf("artifact-store: posix backend: %v", err)
		}
		backend = b
		logger.Info("artifact-store: posix backend", "dir", *dir)
	}

	opts := []artifactstore.Option{}
	if *restricted {
		// A real deployment injects a custody/payment-aware hook; DenyAll is the
		// safe default until one is wired.
		opts = append(opts, artifactstore.WithPosture(artifactstore.PostureRestricted),
			artifactstore.WithAuthorizationHook(artifactstore.DenyAllHook{}))
	}

	srv := artifactstore.NewServer(artifactstore.NewStore(backend), logger, opts...)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("artifact-store listening", "addr", *addr, "posture", postureName(*restricted))
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("artifact-store: serve: %v", err)
	}
}

func postureName(restricted bool) string {
	if restricted {
		return "restricted"
	}
	return "public"
}
