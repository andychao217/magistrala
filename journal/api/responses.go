// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/journal"
)

var _ magistrala.Response = (*pageRes)(nil)

type pageRes struct {
	journal.JournalsPage `json:",inline"`
}

func (res pageRes) Headers() map[string]string {
	return map[string]string{}
}

func (res pageRes) Code() int {
	return http.StatusOK
}

func (res pageRes) Empty() bool {
	return false
}