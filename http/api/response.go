// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/andychao217/magistrala"
)

var _ magistrala.Response = (*publishMessageRes)(nil)

type publishMessageRes struct{}

func (res publishMessageRes) Code() int {
	return http.StatusAccepted
}

func (res publishMessageRes) Headers() map[string]string {
	return map[string]string{}
}

func (res publishMessageRes) Empty() bool {
	return true
}
