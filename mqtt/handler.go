// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package mqtt

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/mproxy/pkg/session"
	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/auth"
	pgclient "github.com/andychao217/magistrala/internal/clients/postgres"
	"github.com/andychao217/magistrala/mqtt/events"
	"github.com/andychao217/magistrala/pkg/errors"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	"github.com/andychao217/magistrala/pkg/messaging"
	clientspg "github.com/andychao217/magistrala/things/postgres"
)

var _ session.Handler = (*handler)(nil)

const protocol = "mqtt"

// Log message formats.
const (
	LogInfoSubscribed   = "subscribed with client_id %s to topics %s"
	LogInfoUnsubscribed = "unsubscribed client_id %s from topics %s"
	LogInfoConnected    = "connected with client_id %s"
	LogInfoDisconnected = "disconnected client_id %s and username %s"
	LogInfoPublished    = "published with client_id %s to the topic %s"
)

// Error wrappers for MQTT errors.
var (
	ErrMalformedSubtopic            = errors.New("malformed subtopic")
	ErrClientNotInitialized         = errors.New("client is not initialized")
	ErrMalformedTopic               = errors.New("malformed topic")
	ErrMissingClientID              = errors.New("client_id not found")
	ErrMissingTopicPub              = errors.New("failed to publish due to missing topic")
	ErrMissingTopicSub              = errors.New("failed to subscribe due to missing topic")
	ErrFailedConnect                = errors.New("failed to connect")
	ErrFailedSubscribe              = errors.New("failed to subscribe")
	ErrFailedUnsubscribe            = errors.New("failed to unsubscribe")
	ErrFailedPublish                = errors.New("failed to publish")
	ErrFailedDisconnect             = errors.New("failed to disconnect")
	ErrFailedPublishDisconnectEvent = errors.New("failed to publish disconnect event")
	ErrFailedParseSubtopic          = errors.New("failed to parse subtopic")
	ErrFailedPublishConnectEvent    = errors.New("failed to publish connect event")
	ErrFailedPublishToMsgBroker     = errors.New("failed to publish to magistrala message broker")
)

var channelRegExp = regexp.MustCompile(`^\/?channels\/([\w\-]+)\/messages(\/[^?]*)?(\?.*)?$`)

// Event implements events.Event interface.
type handler struct {
	publisher messaging.Publisher
	auth      magistrala.AuthzServiceClient
	logger    *slog.Logger
	es        events.EventStore
}

// NewHandler creates new Handler entity.
func NewHandler(publisher messaging.Publisher, es events.EventStore, logger *slog.Logger, authClient magistrala.AuthzServiceClient) session.Handler {
	return &handler{
		es:        es,
		logger:    logger,
		publisher: publisher,
		auth:      authClient,
	}
}

// AuthConnect is called on device connection,
// prior forwarding to the MQTT broker.
func (h *handler) AuthConnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}

	if s.ID == "" {
		return ErrMissingClientID
	}

	pwd := string(s.Password)

	if err := h.es.Connect(ctx, pwd); err != nil {
		h.logger.Error(errors.Wrap(ErrFailedPublishConnectEvent, err).Error())
	}

	return nil
}

// AuthPublish is called on device publish,
// prior forwarding to the MQTT broker.
func (h *handler) AuthPublish(ctx context.Context, topic *string, payload *[]byte) error {
	if topic == nil {
		return ErrMissingTopicPub
	}
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}

	return h.authAccess(ctx, string(s.Password), *topic, auth.PublishPermission)
}

// AuthSubscribe is called on device subscribe,
// prior forwarding to the MQTT broker.
func (h *handler) AuthSubscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}
	if topics == nil || *topics == nil {
		return ErrMissingTopicSub
	}

	for _, v := range *topics {
		if err := h.authAccess(ctx, string(s.Password), v, auth.SubscribePermission); err != nil {
			return err
		}
	}

	return nil
}

// Connect - after client successfully connected.
func (h *handler) Connect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedConnect, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoConnected, s.ID))
	if s.Username != "" {
		updateClientConnectionStatus(ctx, s, "connect", h)
	}
	return nil
}

// Publish - after client successfully published.
func (h *handler) Publish(ctx context.Context, topic *string, payload *[]byte) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedPublish, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoPublished, s.ID, *topic))
	// Topics are in the format:
	// channels/<channel_id>/messages/<subtopic>/.../ct/<content_type>

	channelParts := channelRegExp.FindStringSubmatch(*topic)
	if len(channelParts) < 2 {
		return errors.Wrap(ErrFailedPublish, ErrMalformedTopic)
	}

	chanID := channelParts[1]
	subtopic := channelParts[2]

	subtopic, err := parseSubtopic(subtopic)
	if err != nil {
		return errors.Wrap(ErrFailedParseSubtopic, err)
	}

	msg := messaging.Message{
		Protocol:  protocol,
		Channel:   chanID,
		Subtopic:  subtopic,
		Publisher: s.Username,
		Payload:   *payload,
		Created:   time.Now().UnixNano(),
	}

	if err := h.publisher.Publish(ctx, msg.GetChannel(), &msg); err != nil {
		return errors.Wrap(ErrFailedPublishToMsgBroker, err)
	}

	return nil
}

// Subscribe - after client successfully subscribed.
func (h *handler) Subscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedSubscribe, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoSubscribed, s.ID, strings.Join(*topics, ",")))
	if s.Username != "" {
		updateClientConnectionStatus(ctx, s, "subscribe", h)
	}
	return nil
}

// Unsubscribe - after client unsubscribed.
func (h *handler) Unsubscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	// if s.Username != "" {
	// 	updateClientConnectionStatus(ctx, s, "unsubscribe", h)
	// }
	if !ok {
		return errors.Wrap(ErrFailedUnsubscribe, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoUnsubscribed, s.ID, strings.Join(*topics, ",")))
	return nil
}

// Disconnect - connection with broker or client lost.
func (h *handler) Disconnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if s.Username != "" {
		updateClientConnectionStatus(ctx, s, "disconnect", h)
	}
	if !ok {
		return errors.Wrap(ErrFailedDisconnect, ErrClientNotInitialized)
	}
	h.logger.Error(fmt.Sprintf(LogInfoDisconnected, s.ID, s.Password))
	if err := h.es.Disconnect(ctx, string(s.Password)); err != nil {
		return errors.Wrap(ErrFailedPublishDisconnectEvent, err)
	}
	return nil
}

func (h *handler) authAccess(ctx context.Context, password, topic, action string) error {
	// Topics are in the format:
	// channels/<channel_id>/messages/<subtopic>/.../ct/<content_type>
	if !channelRegExp.MatchString(topic) {
		return ErrMalformedTopic
	}

	channelParts := channelRegExp.FindStringSubmatch(topic)
	if len(channelParts) < 1 {
		return ErrMalformedTopic
	}

	chanID := channelParts[1]

	ar := &magistrala.AuthorizeReq{
		SubjectType: auth.ThingType,
		Permission:  action,
		Subject:     password,
		Object:      chanID,
		ObjectType:  auth.GroupType,
	}
	res, err := h.auth.Authorize(ctx, ar)
	if err != nil {
		return err
	}
	if !res.GetAuthorized() {
		return svcerr.ErrAuthorization
	}

	return nil
}

func parseSubtopic(subtopic string) (string, error) {
	if subtopic == "" {
		return subtopic, nil
	}

	subtopic, err := url.QueryUnescape(subtopic)
	if err != nil {
		return "", ErrMalformedSubtopic
	}
	subtopic = strings.ReplaceAll(subtopic, "/", ".")

	elems := strings.Split(subtopic, ".")
	filteredElems := []string{}
	for _, elem := range elems {
		if elem == "" {
			continue
		}

		if len(elem) > 1 && (strings.Contains(elem, "*") || strings.Contains(elem, ">")) {
			return "", ErrMalformedSubtopic
		}

		filteredElems = append(filteredElems, elem)
	}

	subtopic = strings.Join(filteredElems, ".")
	return subtopic, nil
}

func updateClientConnectionStatus(ctx context.Context, s *session.Session, connectionType string, handler *handler) {
	dbConfig := pgclient.Config{
		Host:        "things-db",
		Port:        "5432",
		User:        "magistrala",
		Pass:        "magistrala",
		Name:        "things",
		SSLMode:     "disable",
		SSLCert:     "",
		SSLKey:      "",
		SSLRootCert: "",
	}
	database, err := pgclient.Connect(dbConfig)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		return
	}
	defer database.Close() // 确保在函数结束时关闭数据库连接

	cRepo := clientspg.NewRepository(database)
	thing, _ := cRepo.RetrieveByIdentity(ctx, s.Username)

	if thing.ID != "" {
		onlineStatus := "0"
		if connectionType == "connect" || connectionType == "subscribe" {
			onlineStatus = "1"
		}
		if thing.Metadata["is_online"] != onlineStatus {
			thing.Metadata["is_online"] = onlineStatus
			_, _ = cRepo.Update(ctx, thing)
		}

		// out_channel 大于1, 且is_channel等于0时，说明是多通道设备，需要把多通道都同时修改onlineStatus
		// 从 Metadata 中获取 "out_channel" 的值，并进行类型断言
		outChannelStr, ok := thing.Metadata["out_channel"].(string)
		fmt.Println("mqtt out_channelStr 1234:", outChannelStr)
		if ok {
			outChannelInt, err := strconv.Atoi(outChannelStr)
			fmt.Println("outChannelInt 1234:", outChannelInt)
			if err != nil {
				fmt.Println("Failed to convert out_channel to int:", err)
			} else {
				if outChannelInt > 1 {
					is_channel, ok := thing.Metadata["is_channel"].(string)
					fmt.Println("mqtt is_channel 1234:", is_channel)
					if ok {
						if is_channel == "0" {
							for i := 2; i <= outChannelInt; i++ {
								fmt.Println("mqtt newThing identity:", thing.Credentials.Identity+"_"+strconv.Itoa(i))
								newThing, _ := cRepo.RetrieveByIdentity(ctx, thing.Credentials.Identity+"_"+strconv.Itoa(i))
								fmt.Println("mqtt newThing:", newThing.ID)
								if newThing.ID != "" {
									newThing.Metadata["is_online"] = onlineStatus
									_, _ = cRepo.Update(ctx, newThing)
								}
							}
						}
					}
				}
			}
		}
	}
}
