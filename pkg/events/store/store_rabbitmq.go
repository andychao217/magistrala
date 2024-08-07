// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//go:build rabbitmq
// +build rabbitmq

package store

import (
	"context"
	"log"
	"log/slog"

	"github.com/andychao217/magistrala/pkg/events"
	"github.com/andychao217/magistrala/pkg/events/rabbitmq"
)

func init() {
	log.Println("The binary was build using rabbitmq as the events store")
}

func NewPublisher(ctx context.Context, url, stream string) (events.Publisher, error) {
	pb, err := rabbitmq.NewPublisher(ctx, url, stream)
	if err != nil {
		return nil, err
	}

	return pb, nil
}

func NewSubscriber(_ context.Context, url string, logger *slog.Logger) (events.Subscriber, error) {
	pb, err := rabbitmq.NewSubscriber(url, logger)
	if err != nil {
		return nil, err
	}

	return pb, nil
}
