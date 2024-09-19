// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package mqtt

import (
	"context"
	"encoding/json"
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
	"github.com/andychao217/magistrala/pkg/clients"
	"github.com/andychao217/magistrala/pkg/errors"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	"github.com/andychao217/magistrala/pkg/messaging"
	clientspg "github.com/andychao217/magistrala/things/postgres"
	proto "github.com/andychao217/websocket_bridge/proto"
	"github.com/mohae/deepcopy"
	gProto "google.golang.org/protobuf/proto"
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
		updateClientConnectionStatus(ctx, s, "connect")
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

	// 处理接收到的消息内容
	h.handleReceivedMessage(ctx, s, &msg)

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
		updateClientConnectionStatus(ctx, s, "subscribe")
	}
	return nil
}

// Unsubscribe - after client unsubscribed.
func (h *handler) Unsubscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedUnsubscribe, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoUnsubscribed, s.ID, strings.Join(*topics, ",")))
	return nil
}

// Disconnect - connection with broker or client lost.
func (h *handler) Disconnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedDisconnect, ErrClientNotInitialized)
	}
	h.logger.Error(fmt.Sprintf(LogInfoDisconnected, s.ID, s.Password))
	if err := h.es.Disconnect(ctx, string(s.Password)); err != nil {
		return errors.Wrap(ErrFailedPublishDisconnectEvent, err)
	}
	if s.Username != "" {
		updateClientConnectionStatus(ctx, s, "disconnect")
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

// 修改在线状态
func updateClientConnectionStatus(ctx context.Context, s *session.Session, connectionType string) {
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

	if thing.ID != "" && !strings.Contains(thing.Name, "Platform") {
		var onlineStatus string
		if connectionType == "connect" || connectionType == "subscribe" {
			onlineStatus = "1"
		} else if connectionType == "disconnect" {
			onlineStatus = "0"
		}
		if onlineStatus == "1" || onlineStatus == "0" {
			thing.Metadata["is_online"] = onlineStatus
			thing.UpdatedAt = time.Now()
			_, _ = cRepo.Update(ctx, thing)

			// out_channel 大于1, 且is_channel等于0时，说明是多通道设备，需要把多通道都同时修改onlineStatus
			// 从 Metadata 中获取 "out_channel" 的值，并进行类型断言
			outChannelStr, ok := thing.Metadata["out_channel"].(string)
			if ok {
				outChannelInt, err := strconv.Atoi(outChannelStr)
				if err != nil {
					fmt.Println("Failed to convert out_channel to int:", err)
				} else {
					if outChannelInt > 1 {
						is_channel, ok := thing.Metadata["is_channel"].(string)
						if ok {
							if is_channel == "0" {
								for i := 2; i <= outChannelInt; i++ {
									newThing, err := cRepo.RetrieveByIdentity(ctx, thing.Credentials.Identity+"_"+strconv.Itoa(i))
									if err != nil {
										continue // 如果检索失败，继续下一个循环
									}
									if newThing.ID != "" {
										newThing.Metadata["is_online"] = onlineStatus
										newThing.UpdatedAt = time.Now()
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
}

// 修改设备信息
func updateClientInfo(ctx context.Context, s *session.Session, newDeviceInfo *proto.DeviceInfo) {
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
	}
	defer database.Close() // 确保在函数结束时关闭数据库连接

	cRepo := clientspg.NewRepository(database)
	thing, _ := cRepo.RetrieveByIdentity(ctx, s.Username)

	if thing.ID != "" && !strings.Contains(thing.Name, "Platform") {
		if info, exists := thing.Metadata["info"]; !exists {
			// 如果不存在，调用 updateInfo()
			updateInfo(ctx, cRepo, thing, newDeviceInfo)
		} else {
			oldDeviceInfo, ok := deepcopy.Copy(info).(*proto.DeviceInfo)
			if !ok {
				fmt.Println("Type assertion to *proto.DeviceInfo failed")
				return
			}

			oldJson, err := json.Marshal(oldDeviceInfo)
			if err != nil {
				fmt.Printf("Failed to marshal oldDeviceInfo: %v\n", err)
				return
			}

			newJson, err := json.Marshal(newDeviceInfo)
			if err != nil {
				fmt.Printf("Failed to marshal newDeviceInfo: %v\n", err)
				return
			}

			if string(oldJson) != string(newJson) {
				updateInfo(ctx, cRepo, thing, newDeviceInfo)
			}
		}
	}
}

func updateInfo(ctx context.Context, cRepo clientspg.Repository, thing clients.Client, newDeviceInfo *proto.DeviceInfo) {
	thing.Metadata["info"] = newDeviceInfo
	thing.UpdatedAt = time.Now()
	if _, err := cRepo.Update(ctx, thing); err != nil {
		fmt.Printf("Failed to update thing: %v\n", err)
		return
	}

	// out_channel 大于1, 且is_channel等于0时，说明是多通道设备，需要把多通道都同时修改onlineStatus
	// 从 Metadata 中获取 "out_channel" 的值，并进行类型断言
	outChannelStr, ok := thing.Metadata["out_channel"].(string)
	if ok {
		outChannelInt, err := strconv.Atoi(outChannelStr)
		if err != nil {
			fmt.Println("Failed to convert out_channel to int:", err)
		} else {
			if outChannelInt > 1 {
				is_channel, ok := thing.Metadata["is_channel"].(string)
				if ok {
					if is_channel == "0" {
						for i := 2; i <= outChannelInt; i++ {
							newThing, err := cRepo.RetrieveByIdentity(ctx, thing.Credentials.Identity+"_"+strconv.Itoa(i))
							if err != nil {
								continue // 如果检索失败，继续下一个循环
							}
							if newThing.ID != "" {
								newThing.Metadata["info"] = newDeviceInfo
								newThing.UpdatedAt = time.Now()
								outChannelData := newDeviceInfo.OutChannel
								channels := outChannelData.Channel
								if len(channels) > 0 {
									if i-1 < len(channels) {
										channelInfo := channels[i-1]
										aliase := channelInfo.Aliase
										newThing.Metadata["aliase"] = newThing.Name + "_" + aliase
										newThing.Name = newThing.Name + "_" + aliase
									}
									thing.Metadata["out_channel_array"] = channels
								}
								if _, err := cRepo.Update(ctx, newThing); err != nil {
									fmt.Printf("Failed to update newThing: %v\n", err)
								}
							}
						}
					}
				}
			}
		}
	}
}

// handleReceivedMessage 处理接收到的 MQTT 消息
func (h *handler) handleReceivedMessage(ctx context.Context, s *session.Session, msg *messaging.Message) {
	type PayloadData struct {
		Data    interface{} `json:"data"`
		Source  string      `json:"source"`
		MsgName string      `json:"msgName"`
	}

	// 定义一个解析函数类型
	type msgParser func([]byte, interface{}) error

	// 映射消息ID到解析函数
	msgParsers := map[string]msgParser{
		"TASK_START":            func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStart)) },
		"TASK_START_REPLY":      func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStartReply)) },
		"TASK_STOP":             func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStop)) },
		"TASK_STOP_REPLY":       func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStopReply)) },
		"TASK_STATUS_GET":       func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStatusGet)) },
		"TASK_STATUS_GET_REPLY": func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskStatusGetReply)) },
		"TASK_SYNC_STATUS_GET":  func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.TaskSyncStatusGet)) },
		"TASK_SYNC_STATUS_GET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.TaskSyncStatusGetReply))
		},
		"SOUND_CONSOLE_TASK_CONTROL_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.SoundConsoleTaskControlReply))
		},
		"SOUND_CONSOLE_TASK_FEEDBACK": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.SoundConsoleTaskFeedback))
		},
		"GET_LOG_REPLY":           func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.GetLogReply)) },
		"DEVICE_LOGIN":            func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.DeviceLogin)) },
		"DEVICE_INFO_GET_REPLY":   func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.DeviceInfoGetReply)) },
		"DEVICE_INFO_UPDATE":      func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.DeviceInfoUpdate)) },
		"DEVICE_RESTORE_REPLY":    func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.DeviceRestoreReply)) },
		"DEVICE_ALIASE_SET_REPLY": func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.DeviceAliaseSetReply)) },
		"LED_CFG_SET_REPLY":       func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.LedCfgSetReply)) },
		"STEREO_CFG_SET_REPLY":    func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.StereoCfgSetReply)) },
		"OUT_CHANNEL_EDIT_REPLY":  func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.OutChannelEditReply)) },
		"IN_CHANNEL_EDIT_REPLY":   func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.InChannelEditReply)) },
		"BLUETOOTH_CFG_SET_REPLY": func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.BluetoothCfgSetReply)) },
		"SPEECH_CFG_SET_REPLY":    func(data []byte, v interface{}) error { return gProto.Unmarshal(data, v.(*proto.SpeechCfgSetReply)) },
		"BLUETOOTH_WHITELIST_ADD_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.BluetoothWhitelistAddReply))
		},
		"BLUETOOTH_WHITELIST_DELETE_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.BluetoothWhitelistDeleteReply))
		},
		"AMP_CHECK_CFG_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.AmpCheckCfgSetReply))
		},
		"AUDIO_MATRIX_CFG_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.AudioMatrixCfgSetReply))
		},
		"RADIO_FREQ_GET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.RadioFreqGetReply))
		},
		"RADIO_FREQ_ADD_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.RadioFreqAddReply))
		},
		"RADIO_FREQ_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.RadioFreqSetReply))
		},
		"RADIO_FREQ_DELETE_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.RadioFreqDeleteReply))
		},
		"U_CHANNEL_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.UChannelSetReply))
		},
		"EQ_CFG_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.EqCfgSetReply))
		},
		"SPEAKER_VOLUME_SET_REPLY": func(data []byte, v interface{}) error {
			return gProto.Unmarshal(data, v.(*proto.SpeakerVolumeSetReply))
		},
	}

	var receivedMsg proto.PbMsg
	err := gProto.Unmarshal(msg.Payload, &receivedMsg)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	msgIdName := proto.MsgId_name[int32(receivedMsg.Id)]
	data := receivedMsg.Data

	unmarshaledData := PayloadData{MsgName: msgIdName, Source: receivedMsg.Source}

	// 使用映射解析消息
	if parser, exists := msgParsers[msgIdName]; exists {
		// 为每种消息类型创建具体的变量
		var msgData interface{}
		switch msgIdName {
		case "TASK_START":
			msgData = &proto.TaskStart{}
		case "TASK_START_REPLY":
			msgData = &proto.TaskStartReply{}
		case "TASK_STOP":
			msgData = &proto.TaskStop{}
		case "TASK_STOP_REPLY":
			msgData = &proto.TaskStopReply{}
		case "TASK_STATUS_GET":
			msgData = &proto.TaskStatusGet{}
		case "TASK_STATUS_GET_REPLY":
			msgData = &proto.TaskStatusGetReply{}
		case "TASK_SYNC_STATUS_GET":
			msgData = &proto.TaskSyncStatusGet{}
		case "TASK_SYNC_STATUS_GET_REPLY":
			msgData = &proto.TaskSyncStatusGetReply{}
		case "SOUND_CONSOLE_TASK_CONTROL_REPLY":
			msgData = &proto.SoundConsoleTaskControlReply{}
		case "SOUND_CONSOLE_TASK_FEEDBACK":
			msgData = &proto.SoundConsoleTaskFeedback{}
		case "GET_LOG_REPLY":
			msgData = &proto.GetLogReply{}
		case "DEVICE_LOGIN":
			msgData = &proto.DeviceLogin{}
		case "DEVICE_INFO_GET_REPLY":
			msgData = &proto.DeviceInfoGetReply{}
		case "DEVICE_INFO_UPDATE":
			msgData = &proto.DeviceInfoUpdate{}
		case "DEVICE_RESTORE_REPLY":
			msgData = &proto.DeviceRestoreReply{}
		case "DEVICE_ALIASE_SET_REPLY":
			msgData = &proto.DeviceAliaseSetReply{}
		case "OUT_CHANNEL_EDIT_REPLY":
			msgData = &proto.OutChannelEditReply{}
		case "IN_CHANNEL_EDIT_REPLY":
			msgData = &proto.InChannelEditReply{}
		case "LED_CFG_SET_REPLY":
			msgData = &proto.LedCfgSetReply{}
		case "AMP_CHECK_CFG_SET_REPLY":
			msgData = &proto.AmpCheckCfgSetReply{}
		case "AUDIO_MATRIX_CFG_SET_REPLY":
			msgData = &proto.AudioMatrixCfgSetReply{}
		case "STEREO_CFG_SET_REPLY":
			msgData = &proto.StereoCfgSetReply{}
		case "BLUETOOTH_CFG_SET_REPLY":
			msgData = &proto.BluetoothCfgSetReply{}
		case "SPEECH_CFG_SET_REPLY":
			msgData = &proto.SpeechCfgSetReply{}
		case "BLUETOOTH_WHITELIST_ADD_REPLY":
			msgData = &proto.BluetoothWhitelistAddReply{}
		case "BLUETOOTH_WHITELIST_DELETE_REPLY":
			msgData = &proto.BluetoothWhitelistDeleteReply{}
		case "RADIO_FREQ_GET_REPLY":
			msgData = &proto.RadioFreqGetReply{}
		case "RADIO_FREQ_ADD_REPLY":
			msgData = &proto.RadioFreqAddReply{}
		case "RADIO_FREQ_SET_REPLY":
			msgData = &proto.RadioFreqSetReply{}
		case "RADIO_FREQ_DELETE_REPLY":
			msgData = &proto.RadioFreqDeleteReply{}
		case "U_CHANNEL_SET_REPLY":
			msgData = &proto.UChannelSetReply{}
		case "EQ_CFG_SET_REPLY":
			msgData = &proto.EqCfgSetReply{}
		case "SPEAKER_VOLUME_SET_REPLY":
			msgData = &proto.SpeakerVolumeSetReply{}
		default:
			fmt.Println("未知的消息类型:", msgIdName)
			return
		}

		err := parser(data, msgData)
		if err != nil {
			fmt.Println("解析错误:", err)
			return
		}
		unmarshaledData.Data = msgData
	}

	// 这里获取 login 状态
	if unmarshaledData.MsgName == "DEVICE_LOGIN" {
		if loginData, ok := unmarshaledData.Data.(*proto.DeviceLogin); ok {
			if loginData.Login {
				updateClientConnectionStatus(ctx, s, "connect")
			} else {
				updateClientConnectionStatus(ctx, s, "disconnect")
			}
		}
	} else if unmarshaledData.MsgName == "DEVICE_INFO_UPDATE" {
		if deviceData, ok := unmarshaledData.Data.(*proto.DeviceInfoUpdate); ok {
			if deviceData.Info != nil {
				updateClientInfo(ctx, s, deviceData.Info)
			}
		}
	} else if unmarshaledData.MsgName == "DEVICE_INFO_GET_REPLY" {
		if deviceData, ok := unmarshaledData.Data.(*proto.DeviceInfoGetReply); ok {
			if deviceData.Info != nil {
				updateClientInfo(ctx, s, deviceData.Info)
			}
		}
	}

	jsonBytes, err := json.Marshal(unmarshaledData)
	if err != nil {
		fmt.Println("转换为 JSON 时发生错误:", err)
		return
	}

	jsonString := string(jsonBytes)
	fmt.Println("1234ddd5 Received jsonString: ", jsonString)
}
