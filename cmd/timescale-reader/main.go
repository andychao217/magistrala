// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package main contains timescale-reader main function to start the timescale-reader service.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	chclient "github.com/andychao217/callhome/pkg/client"
	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/internal"
	pgclient "github.com/andychao217/magistrala/internal/clients/postgres"
	"github.com/andychao217/magistrala/internal/server"
	httpserver "github.com/andychao217/magistrala/internal/server/http"
	mglog "github.com/andychao217/magistrala/logger"
	"github.com/andychao217/magistrala/pkg/auth"
	"github.com/andychao217/magistrala/pkg/uuid"
	"github.com/andychao217/magistrala/readers"
	"github.com/andychao217/magistrala/readers/api"
	"github.com/andychao217/magistrala/readers/timescale"
	"github.com/caarlos0/env/v10"
	"github.com/jmoiron/sqlx"
	"golang.org/x/sync/errgroup"
)

const (
	svcName        = "timescaledb-reader"
	envPrefixDB    = "MG_TIMESCALE_"
	envPrefixHTTP  = "MG_TIMESCALE_READER_HTTP_"
	envPrefixAuth  = "MG_AUTH_GRPC_"
	envPrefixAuthz = "MG_THINGS_AUTH_GRPC_"
	defDB          = "messages"
	defSvcHTTPPort = "9011"
)

type config struct {
	LogLevel      string `env:"MG_TIMESCALE_READER_LOG_LEVEL"    envDefault:"info"`
	SendTelemetry bool   `env:"MG_SEND_TELEMETRY"                envDefault:"true"`
	InstanceID    string `env:"MG_TIMESCALE_READER_INSTANCE_ID"  envDefault:""`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to init logger: %s", err.Error())
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			logger.Error(fmt.Sprintf("failed to generate instanceID: %s", err))
			exitCode = 1
			return
		}
	}

	dbConfig := pgclient.Config{Name: defDB}
	if err := env.ParseWithOptions(&dbConfig, env.Options{Prefix: envPrefixDB}); err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	db, err := pgclient.Connect(dbConfig)
	if err != nil {
		logger.Error(err.Error())
	}
	defer db.Close()

	repo := newService(db, logger)

	authConfig := auth.Config{}
	if err := env.ParseWithOptions(&authConfig, env.Options{Prefix: envPrefixAuth}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s auth configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	ac, acHandler, err := auth.Setup(authConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer acHandler.Close()

	logger.Info("Successfully connected to auth grpc server " + acHandler.Secure())

	authConfig = auth.Config{}
	if err := env.ParseWithOptions(&authConfig, env.Options{Prefix: envPrefixAuthz}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s auth configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	tc, tcHandler, err := auth.SetupAuthz(authConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer tcHandler.Close()

	logger.Info("Successfully connected to things grpc server " + tcHandler.Secure())

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.ParseWithOptions(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s HTTP server configuration : %s", svcName, err))
		exitCode = 1
		return
	}
	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, api.MakeHandler(repo, ac, tc, svcName, cfg.InstanceID), logger)

	if cfg.SendTelemetry {
		chc := chclient.New(svcName, magistrala.Version, logger, cancel)
		go chc.CallHome(ctx)
	}

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("Timescale reader service terminated: %s", err))
	}
}

func newService(db *sqlx.DB, logger *slog.Logger) readers.MessageRepository {
	svc := timescale.New(db)
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics("timescale", "message_reader")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}
