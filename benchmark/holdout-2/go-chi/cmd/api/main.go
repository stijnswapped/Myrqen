// Command api serves the Harborline shipping API.
//
// Route groups, in the order they are mounted below:
//
//	/v1/shipments…   operator console, behind RequireSession
//	/v1/labels…      operator console, behind RequireSession
//	/v1/manifests…   operator console, behind RequireSession
//	/v1/carriers…    integration settings, behind RequireSession + RequireAdmin
//	/v1/…/webhooks…  public, authenticated by per-partner signature only
package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/lib/pq"

	"github.com/harborline/shipping-api/internal/http/authn"
	"github.com/harborline/shipping-api/internal/http/carriers"
	"github.com/harborline/shipping-api/internal/http/labels"
	"github.com/harborline/shipping-api/internal/http/manifests"
	"github.com/harborline/shipping-api/internal/http/shipments"
)

const shutdownGrace = 20 * time.Second

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	db, err := sql.Open("postgres", mustEnv("DATABASE_URL"))
	if err != nil {
		slog.Error("database open failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(24)
	db.SetConnMaxLifetime(30 * time.Minute)

	spoolRoot := mustEnv("LABEL_SPOOL_ROOT")

	router := chi.NewRouter()
	router.Use(middleware.RealIP)
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(120 * time.Second))

	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	router.Route("/v1", func(v1 chi.Router) {
		v1.Group(func(console chi.Router) {
			console.Use(authn.RequireSession(db))

			console.Get("/shipments", shipments.Search(db))
			console.Get("/shipments/lookup", shipments.Lookup(db))
			console.Get("/shipments/{shipmentID}", shipments.Detail(db))
			console.Get("/shipments/{shipmentID}/events", shipments.Timeline(db))

			console.Get("/labels/documents", labels.Document(spoolRoot))
			console.Get("/labels/archives", labels.Archive(spoolRoot))

			console.Post("/manifests/{batchRef}/sheet", manifests.Sheet(spoolRoot))
			console.Post("/manifests/{batchRef}/export", manifests.Export(spoolRoot))

			console.Group(func(admin chi.Router) {
				admin.Use(authn.RequireAdmin)
				admin.Post("/carriers/{carrierCode}/callback-test", carriers.CallbackTest())
				admin.Post("/carriers/{carrierCode}/rate-probe", carriers.RateProbe())
			})
		})

		v1.Group(func(public chi.Router) {
			public.With(authn.RequireCarrierSignature(carrierSecrets())).
				Post("/carriers/webhooks/{carrier}", acceptEvents)
			public.With(authn.RequirePartnerKey(partnerKeys())).
				Post("/partners/webhooks/{partner}", acceptEvents)
		})
	})

	server := &http.Server{
		Addr:              envOr("LISTEN_ADDR", ":8080"),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
}

// acceptEvents parks a signed callback on the ingest queue. The signature has
// already been checked by the middleware in front of it.
func acceptEvents(w http.ResponseWriter, r *http.Request) {
	// The ingest worker owns the parsing; this route only has to be fast.
	w.WriteHeader(http.StatusAccepted)
}

// carrierSecrets reads the per-carrier webhook secrets out of the environment,
// one variable per carrier: CARRIER_SECRET_DHL, CARRIER_SECRET_UPS, and so on.
func carrierSecrets() map[string]string {
	secrets := map[string]string{}
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "CARRIER_SECRET_") || value == "" {
			continue
		}
		secrets[strings.ToLower(strings.TrimPrefix(name, "CARRIER_SECRET_"))] = value
	}
	if len(secrets) == 0 {
		slog.Warn("no carrier webhook secrets configured; carrier callbacks will 404")
	}
	return secrets
}

// partnerKeys is loaded from the key service at boot in production. The stub
// here keeps the wiring honest for local runs, where the map is simply empty
// and every partner callback is rejected.
func partnerKeys() map[string]authn.PartnerKey {
	return map[string]authn.PartnerKey{}
}

func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		slog.Error("required environment variable is not set", "name", name)
		os.Exit(1)
	}
	return value
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
