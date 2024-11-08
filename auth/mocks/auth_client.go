// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	context "context"

	"github.com/andychao217/magistrala"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

const InvalidValue = "invalid"

var _ magistrala.AuthServiceClient = (*AuthClient)(nil)

type AuthClient struct {
	mock.Mock
}

func (m *AuthClient) Issue(ctx context.Context, in *magistrala.IssueReq, opts ...grpc.CallOption) (*magistrala.Token, error) {
	ret := m.Called(ctx, in)
	if in.GetUserId() == InvalidValue || in.GetUserId() == "" {
		return &magistrala.Token{}, svcerr.ErrAuthentication
	}

	return ret.Get(0).(*magistrala.Token), ret.Error(1)
}

func (m *AuthClient) Refresh(ctx context.Context, in *magistrala.RefreshReq, opts ...grpc.CallOption) (*magistrala.Token, error) {
	ret := m.Called(ctx, in)
	if in.GetRefreshToken() == InvalidValue || in.GetRefreshToken() == "" {
		return &magistrala.Token{}, svcerr.ErrAuthentication
	}

	return ret.Get(0).(*magistrala.Token), ret.Error(1)
}

func (m *AuthClient) Identify(ctx context.Context, in *magistrala.IdentityReq, opts ...grpc.CallOption) (*magistrala.IdentityRes, error) {
	ret := m.Called(ctx, in)
	if in.GetToken() == InvalidValue || in.GetToken() == "" {
		return &magistrala.IdentityRes{}, svcerr.ErrAuthentication
	}

	return ret.Get(0).(*magistrala.IdentityRes), ret.Error(1)
}

func (m *AuthClient) Authorize(ctx context.Context, in *magistrala.AuthorizeReq, opts ...grpc.CallOption) (*magistrala.AuthorizeRes, error) {
	ret := m.Called(ctx, in)
	if in.GetSubject() == InvalidValue || in.GetSubject() == "" {
		return &magistrala.AuthorizeRes{Authorized: false}, svcerr.ErrAuthorization
	}
	if in.GetObject() == InvalidValue || in.GetObject() == "" {
		return &magistrala.AuthorizeRes{Authorized: false}, svcerr.ErrAuthorization
	}

	return ret.Get(0).(*magistrala.AuthorizeRes), ret.Error(1)
}

func (m *AuthClient) AddPolicy(ctx context.Context, in *magistrala.AddPolicyReq, opts ...grpc.CallOption) (*magistrala.AddPolicyRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.AddPolicyRes), ret.Error(1)
}

func (m *AuthClient) AddPolicies(ctx context.Context, in *magistrala.AddPoliciesReq, opts ...grpc.CallOption) (*magistrala.AddPoliciesRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.AddPoliciesRes), ret.Error(1)
}

func (m *AuthClient) DeletePolicy(ctx context.Context, in *magistrala.DeletePolicyReq, opts ...grpc.CallOption) (*magistrala.DeletePolicyRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.DeletePolicyRes), ret.Error(1)
}

func (m *AuthClient) DeletePolicies(ctx context.Context, in *magistrala.DeletePoliciesReq, opts ...grpc.CallOption) (*magistrala.DeletePoliciesRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.DeletePoliciesRes), ret.Error(1)
}

func (m *AuthClient) ListObjects(ctx context.Context, in *magistrala.ListObjectsReq, opts ...grpc.CallOption) (*magistrala.ListObjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.ListObjectsRes), ret.Error(1)
}

func (m *AuthClient) ListAllObjects(ctx context.Context, in *magistrala.ListObjectsReq, opts ...grpc.CallOption) (*magistrala.ListObjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.ListObjectsRes), ret.Error(1)
}

func (m *AuthClient) CountObjects(ctx context.Context, in *magistrala.CountObjectsReq, opts ...grpc.CallOption) (*magistrala.CountObjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.CountObjectsRes), ret.Error(1)
}

func (m *AuthClient) ListSubjects(ctx context.Context, in *magistrala.ListSubjectsReq, opts ...grpc.CallOption) (*magistrala.ListSubjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.ListSubjectsRes), ret.Error(1)
}

func (m *AuthClient) ListAllSubjects(ctx context.Context, in *magistrala.ListSubjectsReq, opts ...grpc.CallOption) (*magistrala.ListSubjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.ListSubjectsRes), ret.Error(1)
}

func (m *AuthClient) CountSubjects(ctx context.Context, in *magistrala.CountSubjectsReq, opts ...grpc.CallOption) (*magistrala.CountSubjectsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.CountSubjectsRes), ret.Error(1)
}

func (m *AuthClient) ListPermissions(ctx context.Context, in *magistrala.ListPermissionsReq, opts ...grpc.CallOption) (*magistrala.ListPermissionsRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.ListPermissionsRes), ret.Error(1)
}

func (m *AuthClient) DeleteEntityPolicies(ctx context.Context, in *magistrala.DeleteEntityPoliciesReq, opts ...grpc.CallOption) (*magistrala.DeletePolicyRes, error) {
	ret := m.Called(ctx, in)

	return ret.Get(0).(*magistrala.DeletePolicyRes), ret.Error(1)
}
