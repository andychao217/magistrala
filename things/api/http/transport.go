// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"log/slog"
	"net/http"

	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/pkg/groups"
	"github.com/andychao217/magistrala/things"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for Things and Groups API endpoints.
func MakeHandler(tsvc things.Service, grps groups.Service, mux *chi.Mux, logger *slog.Logger, instanceID string) http.Handler {
	clientsHandler(tsvc, mux, logger)
	groupsHandler(grps, mux, logger)

	mux.Get("/health", magistrala.Health("things", instanceID))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}
