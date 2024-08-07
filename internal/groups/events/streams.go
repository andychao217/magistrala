// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/andychao217/magistrala/pkg/events"
	"github.com/andychao217/magistrala/pkg/events/store"
	"github.com/andychao217/magistrala/pkg/groups"
)

var _ groups.Service = (*eventStore)(nil)

type eventStore struct {
	events.Publisher
	svc groups.Service
}

// NewEventStoreMiddleware returns wrapper around things service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc groups.Service, url, streamID string) (groups.Service, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}

	return &eventStore{
		svc:       svc,
		Publisher: publisher,
	}, nil
}

func (es eventStore) CreateGroup(ctx context.Context, token, kind string, group groups.Group) (groups.Group, error) {
	group, err := es.svc.CreateGroup(ctx, token, kind, group)
	if err != nil {
		return group, err
	}

	event := createGroupEvent{
		group,
	}

	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es eventStore) UpdateGroup(ctx context.Context, token string, group groups.Group) (groups.Group, error) {
	group, err := es.svc.UpdateGroup(ctx, token, group)
	if err != nil {
		return group, err
	}

	event := updateGroupEvent{
		group,
	}

	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es eventStore) ViewGroup(ctx context.Context, token, id string) (groups.Group, error) {
	group, err := es.svc.ViewGroup(ctx, token, id)
	if err != nil {
		return group, err
	}
	event := viewGroupEvent{
		group,
	}

	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es eventStore) ViewGroupPerms(ctx context.Context, token, id string) ([]string, error) {
	permissions, err := es.svc.ViewGroupPerms(ctx, token, id)
	if err != nil {
		return permissions, err
	}
	event := viewGroupPermsEvent{
		permissions,
	}

	if err := es.Publish(ctx, event); err != nil {
		return permissions, err
	}

	return permissions, nil
}

func (es eventStore) ListGroups(ctx context.Context, token, memberKind, memberID string, pm groups.Page) (groups.Page, error) {
	gp, err := es.svc.ListGroups(ctx, token, memberKind, memberID, pm)
	if err != nil {
		return gp, err
	}
	event := listGroupEvent{
		pm,
	}

	if err := es.Publish(ctx, event); err != nil {
		return gp, err
	}

	return gp, nil
}

func (es eventStore) ListMembers(ctx context.Context, token, groupID, permission, memberKind string) (groups.MembersPage, error) {
	mp, err := es.svc.ListMembers(ctx, token, groupID, permission, memberKind)
	if err != nil {
		return mp, err
	}
	event := listGroupMembershipEvent{
		groupID, permission, memberKind,
	}

	if err := es.Publish(ctx, event); err != nil {
		return mp, err
	}

	return mp, nil
}

func (es eventStore) EnableGroup(ctx context.Context, token, id string) (groups.Group, error) {
	group, err := es.svc.EnableGroup(ctx, token, id)
	if err != nil {
		return group, err
	}

	return es.changeStatus(ctx, group)
}

func (es eventStore) Assign(ctx context.Context, token, groupID, relation, memberKind string, memberIDs ...string) error {
	if err := es.svc.Assign(ctx, token, groupID, relation, memberKind, memberIDs...); err != nil {
		return err
	}

	event := assignEvent{
		groupID:   groupID,
		memberIDs: memberIDs,
	}

	if err := es.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}

func (es eventStore) Unassign(ctx context.Context, token, groupID, relation, memberKind string, memberIDs ...string) error {
	if err := es.svc.Unassign(ctx, token, groupID, relation, memberKind, memberIDs...); err != nil {
		return err
	}

	event := unassignEvent{
		groupID:   groupID,
		memberIDs: memberIDs,
	}

	if err := es.Publish(ctx, event); err != nil {
		return err
	}
	return es.svc.Unassign(ctx, token, groupID, relation, memberKind, memberIDs...)
}

func (es eventStore) DisableGroup(ctx context.Context, token, id string) (groups.Group, error) {
	group, err := es.svc.DisableGroup(ctx, token, id)
	if err != nil {
		return group, err
	}

	return es.changeStatus(ctx, group)
}

func (es eventStore) changeStatus(ctx context.Context, group groups.Group) (groups.Group, error) {
	event := changeStatusGroupEvent{
		id:        group.ID,
		updatedAt: group.UpdatedAt,
		updatedBy: group.UpdatedBy,
		status:    group.Status.String(),
	}

	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es eventStore) DeleteGroup(ctx context.Context, token, id string) error {
	if err := es.svc.DeleteGroup(ctx, token, id); err != nil {
		return err
	}
	if err := es.Publish(ctx, deleteGroupEvent{id}); err != nil {
		return err
	}
	return nil
}
