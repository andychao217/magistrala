// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"log/slog"
	"net/http"

	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/auth"
	"github.com/andychao217/magistrala/auth/api/http/domains"
	"github.com/andychao217/magistrala/auth/api/http/keys"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc auth.Service, logger *slog.Logger, instanceID string) http.Handler {
	mux := chi.NewRouter()

	mux = keys.MakeHandler(svc, mux, logger)
	mux = domains.MakeHandler(svc, mux, logger)

	mux.Get("/health", magistrala.Health("auth", instanceID))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}
