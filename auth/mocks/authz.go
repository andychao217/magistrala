// Code generated by mockery v2.42.1. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	auth "github.com/andychao217/magistrala/auth"

	mock "github.com/stretchr/testify/mock"
)

// Authz is an autogenerated mock type for the Authz type
type Authz struct {
	mock.Mock
}

// AddPolicies provides a mock function with given fields: ctx, prs
func (_m *Authz) AddPolicies(ctx context.Context, prs []auth.PolicyReq) error {
	ret := _m.Called(ctx, prs)

	if len(ret) == 0 {
		panic("no return value specified for AddPolicies")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []auth.PolicyReq) error); ok {
		r0 = rf(ctx, prs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddPolicy provides a mock function with given fields: ctx, pr
func (_m *Authz) AddPolicy(ctx context.Context, pr auth.PolicyReq) error {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for AddPolicy")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) error); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Authorize provides a mock function with given fields: ctx, pr
func (_m *Authz) Authorize(ctx context.Context, pr auth.PolicyReq) error {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for Authorize")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) error); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CountObjects provides a mock function with given fields: ctx, pr
func (_m *Authz) CountObjects(ctx context.Context, pr auth.PolicyReq) (uint64, error) {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for CountObjects")
	}

	var r0 uint64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) (uint64, error)); ok {
		return rf(ctx, pr)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) uint64); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq) error); ok {
		r1 = rf(ctx, pr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CountSubjects provides a mock function with given fields: ctx, pr
func (_m *Authz) CountSubjects(ctx context.Context, pr auth.PolicyReq) (uint64, error) {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for CountSubjects")
	}

	var r0 uint64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) (uint64, error)); ok {
		return rf(ctx, pr)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) uint64); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq) error); ok {
		r1 = rf(ctx, pr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteEntityPolicies provides a mock function with given fields: ctx, entityType, id
func (_m *Authz) DeleteEntityPolicies(ctx context.Context, entityType string, id string) error {
	ret := _m.Called(ctx, entityType, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteEntityPolicies")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, entityType, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletePolicies provides a mock function with given fields: ctx, prs
func (_m *Authz) DeletePolicies(ctx context.Context, prs []auth.PolicyReq) error {
	ret := _m.Called(ctx, prs)

	if len(ret) == 0 {
		panic("no return value specified for DeletePolicies")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []auth.PolicyReq) error); ok {
		r0 = rf(ctx, prs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletePolicy provides a mock function with given fields: ctx, pr
func (_m *Authz) DeletePolicy(ctx context.Context, pr auth.PolicyReq) error {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for DeletePolicy")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) error); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ListAllObjects provides a mock function with given fields: ctx, pr
func (_m *Authz) ListAllObjects(ctx context.Context, pr auth.PolicyReq) (auth.PolicyPage, error) {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for ListAllObjects")
	}

	var r0 auth.PolicyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) (auth.PolicyPage, error)); ok {
		return rf(ctx, pr)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) auth.PolicyPage); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Get(0).(auth.PolicyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq) error); ok {
		r1 = rf(ctx, pr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListAllSubjects provides a mock function with given fields: ctx, pr
func (_m *Authz) ListAllSubjects(ctx context.Context, pr auth.PolicyReq) (auth.PolicyPage, error) {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for ListAllSubjects")
	}

	var r0 auth.PolicyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) (auth.PolicyPage, error)); ok {
		return rf(ctx, pr)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq) auth.PolicyPage); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Get(0).(auth.PolicyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq) error); ok {
		r1 = rf(ctx, pr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListObjects provides a mock function with given fields: ctx, pr, nextPageToken, limit
func (_m *Authz) ListObjects(ctx context.Context, pr auth.PolicyReq, nextPageToken string, limit uint64) (auth.PolicyPage, error) {
	ret := _m.Called(ctx, pr, nextPageToken, limit)

	if len(ret) == 0 {
		panic("no return value specified for ListObjects")
	}

	var r0 auth.PolicyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, string, uint64) (auth.PolicyPage, error)); ok {
		return rf(ctx, pr, nextPageToken, limit)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, string, uint64) auth.PolicyPage); ok {
		r0 = rf(ctx, pr, nextPageToken, limit)
	} else {
		r0 = ret.Get(0).(auth.PolicyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq, string, uint64) error); ok {
		r1 = rf(ctx, pr, nextPageToken, limit)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListPermissions provides a mock function with given fields: ctx, pr, filterPermission
func (_m *Authz) ListPermissions(ctx context.Context, pr auth.PolicyReq, filterPermission []string) (auth.Permissions, error) {
	ret := _m.Called(ctx, pr, filterPermission)

	if len(ret) == 0 {
		panic("no return value specified for ListPermissions")
	}

	var r0 auth.Permissions
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, []string) (auth.Permissions, error)); ok {
		return rf(ctx, pr, filterPermission)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, []string) auth.Permissions); ok {
		r0 = rf(ctx, pr, filterPermission)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(auth.Permissions)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq, []string) error); ok {
		r1 = rf(ctx, pr, filterPermission)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListSubjects provides a mock function with given fields: ctx, pr, nextPageToken, limit
func (_m *Authz) ListSubjects(ctx context.Context, pr auth.PolicyReq, nextPageToken string, limit uint64) (auth.PolicyPage, error) {
	ret := _m.Called(ctx, pr, nextPageToken, limit)

	if len(ret) == 0 {
		panic("no return value specified for ListSubjects")
	}

	var r0 auth.PolicyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, string, uint64) (auth.PolicyPage, error)); ok {
		return rf(ctx, pr, nextPageToken, limit)
	}
	if rf, ok := ret.Get(0).(func(context.Context, auth.PolicyReq, string, uint64) auth.PolicyPage); ok {
		r0 = rf(ctx, pr, nextPageToken, limit)
	} else {
		r0 = ret.Get(0).(auth.PolicyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, auth.PolicyReq, string, uint64) error); ok {
		r1 = rf(ctx, pr, nextPageToken, limit)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewAuthz creates a new instance of Authz. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthz(t interface {
	mock.TestingT
	Cleanup(func())
}) *Authz {
	mock := &Authz{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
