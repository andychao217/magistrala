// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/internal/apiutil"
	"github.com/andychao217/magistrala/pkg/errors"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	"github.com/andychao217/magistrala/readers"
	"github.com/go-kit/kit/endpoint"
)

func listMessagesEndpoint(svc readers.MessageRepository, uauth magistrala.AuthServiceClient, taauth magistrala.AuthzServiceClient) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMessagesReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		if err := authorize(ctx, req, uauth, taauth); err != nil {
			return nil, errors.Wrap(svcerr.ErrAuthorization, err)
		}

		page, err := svc.ReadAll(req.chanID, req.pageMeta)
		if err != nil {
			return nil, err
		}

		return pageRes{
			PageMetadata: page.PageMetadata,
			Total:        page.Total,
			Messages:     page.Messages,
		}, nil
	}
}
