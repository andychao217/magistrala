// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package things

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/andychao217/magistrala"
	"github.com/andychao217/magistrala/auth"
	pgclient "github.com/andychao217/magistrala/internal/clients/postgres"
	mgclients "github.com/andychao217/magistrala/pkg/clients"
	"github.com/andychao217/magistrala/pkg/errors"
	repoerr "github.com/andychao217/magistrala/pkg/errors/repository"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	mggroups "github.com/andychao217/magistrala/pkg/groups"
	"github.com/andychao217/magistrala/things/postgres"
	"github.com/mohae/deepcopy"
	"golang.org/x/sync/errgroup"
)

var (
	errAddPolicies    = errors.New("failed to add policies")
	errRemovePolicies = errors.New("failed to remove the policies")
)

type service struct {
	auth        magistrala.AuthServiceClient
	clients     postgres.Repository
	clientCache Cache
	idProvider  magistrala.IDProvider
	grepo       mggroups.Repository
}

type Channel struct {
	ID        string `json:"id"`
	DomainID  string `json:"domain_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Status    string `json:"status"`
}

type ChannelListResponse struct {
	Total    int       `json:"total"`
	Offset   int       `json:"offset"`
	Channels []Channel `json:"groups"`
}

// 获取channel id列表
func getChannelIDs(token string) ([]string, error) {
	// 创建domain时默认创建一个channel
	// 要发送的数据
	// 只默认关联default_channel
	url := "http://things:9000/channels?limit=1000&name=default_channel"
	// 创建HTTP GET请求
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Println(err)
		return []string{}, err
	}
	// 在请求头中添加token
	req.Header.Set("Authorization", "Bearer "+token) // 假设token是一个Bearer token
	// 创建一个HTTP客户端
	client := &http.Client{}
	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return []string{}, err
	}
	defer resp.Body.Close()
	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return []string{}, err
	}
	// 打印响应体
	fmt.Println(string(body))

	// 创建一个Response变量来存储解析后的数据
	var response ChannelListResponse
	// 使用json.Unmarshal来解析JSON字符串到Go结构体
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Printf("Error unmarshaling JSON: %s\n", err)
		return []string{}, err
	}
	var channelIDs []string
	for _, channel := range response.Channels {
		if channel.Name == "default_channel" {
			channelIDs = append(channelIDs, channel.ID)
		}
	}
	// 打印结果
	fmt.Println(channelIDs)

	return channelIDs, err
}

// 新建things后默认关联channels
func connectThingsAndChannels(thingIDs []string, channelIDs []string, token string) {
	for _, thingID := range thingIDs {
		for _, channelID := range channelIDs {
			// 设置请求URL
			url := "http://things:9000/channels/" + channelID + "/things/" + thingID + "/connect"
			// 创建一个HTTP客户端
			client := &http.Client{}
			// 创建一个请求
			req, err := http.NewRequest(http.MethodPost, url, nil)
			if err != nil {
				fmt.Printf("http.NewRequest: %s\n", err)
			}
			// 设置请求头
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			// 发送请求
			_, err = client.Do(req)
			if err != nil {
				fmt.Printf("client.Do: %s\n", err)
			}
		}
	}
}

// NewService returns a new Clients service implementation.
func NewService(uauth magistrala.AuthServiceClient, c postgres.Repository, grepo mggroups.Repository, tcache Cache, idp magistrala.IDProvider) Service {
	return service{
		auth:        uauth,
		clients:     c,
		grepo:       grepo,
		clientCache: tcache,
		idProvider:  idp,
	}
}

func (svc service) Authorize(ctx context.Context, req *magistrala.AuthorizeReq) (string, error) {
	thingID, err := svc.Identify(ctx, req.GetSubject())
	if err != nil {
		return "", err
	}

	r := &magistrala.AuthorizeReq{
		SubjectType: auth.GroupType,
		Subject:     req.GetObject(),
		ObjectType:  auth.ThingType,
		Object:      thingID,
		Permission:  req.GetPermission(),
	}
	resp, err := svc.auth.Authorize(ctx, r)
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !resp.GetAuthorized() {
		return "", svcerr.ErrAuthorization
	}

	return thingID, nil
}

func (svc service) CreateThings(ctx context.Context, token string, cls ...mgclients.Client) ([]mgclients.Client, error) {
	user, err := svc.identify(ctx, token)
	if err != nil {
		return []mgclients.Client{}, err
	}
	// If domain is disabled , then this authorization will fail for all non-admin domain users
	if _, err := svc.authorize(ctx, "", auth.UserType, auth.UsersKind, user.GetId(), auth.MembershipPermission, auth.DomainType, user.GetDomainId()); err != nil {
		return []mgclients.Client{}, err
	}

	var clients []mgclients.Client
	var query []mgclients.Client

	for _, c := range cls {
		// 使用 deepcopy 进行深拷贝
		oriQuery := deepcopy.Copy(c).(mgclients.Client)
		query = append(query, oriQuery)
		// 将 query 转换为 JSON 字符串
		jsonData, _ := json.Marshal(query)
		// 打印 JSON 字符串
		fmt.Println("query 123: ", string(jsonData))
		// 处理 multi-channel logic
		if outChannel, ok := oriQuery.Metadata["out_channel"].(string); ok {
			// 转换为整数
			outChannelNum, _ := strconv.Atoi(outChannel)
			if outChannelNum > 1 {
				// 根据 out_channel 生成多个通道设备
				if outChannelArray, ok := oriQuery.Metadata["out_channel_array"].([]interface{}); ok {
					for j := 2; j <= len(outChannelArray); j++ {
						// 创建新设备，使用结构体的值进行复制
						newThing := deepcopy.Copy(oriQuery).(mgclients.Client)
						if channelInfo, ok := outChannelArray[j-1].(map[string]interface{}); ok {
							// 获取 alias
							alias := channelInfo["aliase"].(string)
							name := oriQuery.Name
							newThing.Name = fmt.Sprintf("%s_%s", name, alias)
							newThing.Credentials.Identity = fmt.Sprintf("%s_%d", oriQuery.Credentials.Identity, j)
							newThing.Credentials.Secret = fmt.Sprintf("%s_%d", oriQuery.Credentials.Secret, j)
							newThing.Metadata["aliase"] = fmt.Sprintf("%s_%s", name, alias)
							newThing.Metadata["is_channel"] = "1"
							query = append(query, newThing)

							// 将 query 转换为 JSON 字符串
							jsonData, _ := json.Marshal(query)
							// 打印 JSON 字符串
							fmt.Println("query 234: ", string(jsonData))
						}
					}
				}
			}
		}
	}

	// 处理每个设备的基本信息
	for _, c := range query {
		if c.ID == "" {
			clientID, err := svc.idProvider.ID()
			if err != nil {
				return []mgclients.Client{}, err
			}
			c.ID = clientID
		}
		if c.Credentials.Secret == "" {
			key, err := svc.idProvider.ID()
			if err != nil {
				return []mgclients.Client{}, err
			}
			c.Credentials.Secret = key
		}
		if c.Status != mgclients.DisabledStatus && c.Status != mgclients.EnabledStatus {
			return []mgclients.Client{}, svcerr.ErrInvalidStatus
		}
		c.Domain = user.GetDomainId()
		c.CreatedAt = time.Now()
		clients = append(clients, c)
	}

	// 过滤出 Credentials.Identity 不为空的 Client
	var filteredClients []mgclients.Client
	for _, client := range clients {
		if client.Credentials.Identity != "" {
			filteredClients = append(filteredClients, client)
		}
	}

	saved, err := svc.clients.Save(ctx, filteredClients...)
	if err != nil {
		return nil, errors.Wrap(repoerr.ErrCreateEntity, err)
	}

	policies := magistrala.AddPoliciesReq{}
	for _, c := range saved {
		policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
			Domain:      user.GetDomainId(),
			SubjectType: auth.UserType,
			Subject:     user.GetId(),
			Relation:    auth.AdministratorRelation,
			ObjectKind:  auth.NewThingKind,
			ObjectType:  auth.ThingType,
			Object:      c.ID,
		})
		policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
			Domain:      user.GetDomainId(),
			SubjectType: auth.DomainType,
			Subject:     user.GetDomainId(),
			Relation:    auth.DomainRelation,
			ObjectType:  auth.ThingType,
			Object:      c.ID,
		})
	}
	if _, err := svc.auth.AddPolicies(ctx, &policies); err != nil {
		return nil, errors.Wrap(errAddPolicies, err)
	}

	channelIDs, err := getChannelIDs(token)
	if err != nil {
		fmt.Println("error get ChannelIDs")
	}
	//新建things时，自动连接该domain下的default Channel
	thingIDs := make([]string, len(saved))
	for i, thing := range saved {
		thingIDs[i] = thing.ID
	}
	if len(thingIDs) > 0 && len(channelIDs) > 0 {
		connectThingsAndChannels(thingIDs, channelIDs, token)
	}

	return saved, nil
}

func (svc service) ViewClient(ctx context.Context, token, id string) (mgclients.Client, error) {
	_, err := svc.authorize(ctx, "", auth.UserType, auth.TokenKind, token, auth.ViewPermission, auth.ThingType, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	client, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return client, nil
}

func (svc service) ViewClientPerms(ctx context.Context, token, id string) ([]string, error) {
	res, err := svc.identify(ctx, token)
	if err != nil {
		return nil, err
	}

	permissions, err := svc.listUserThingPermission(ctx, res.GetId(), id)
	if err != nil {
		return nil, err
	}
	if len(permissions) == 0 {
		return nil, svcerr.ErrAuthorization
	}
	return permissions, nil
}

func (svc service) ListClients(ctx context.Context, token, reqUserID string, pm mgclients.Page, showFullData string) (mgclients.ClientsPage, error) {
	var ids []string

	res, err := svc.identify(ctx, token)
	if err != nil {
		return mgclients.ClientsPage{}, err
	}

	switch {
	case (reqUserID != "" && reqUserID != res.GetUserId()):
		// Check user is admin of domain, if yes then show listing on domain context
		if _, err := svc.authorize(ctx, "", auth.UserType, auth.UsersKind, res.GetId(), auth.AdminPermission, auth.DomainType, res.GetDomainId()); err != nil {
			return mgclients.ClientsPage{}, err
		}
		rtids, err := svc.listClientIDs(ctx, auth.EncodeDomainUserID(res.GetDomainId(), reqUserID), pm.Permission)
		if err != nil {
			return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrNotFound, err)
		}
		ids, err = svc.filterAllowedThingIDs(ctx, res.GetId(), pm.Permission, rtids)
		if err != nil {
			return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrNotFound, err)
		}
	default:
		err := svc.checkSuperAdmin(ctx, res.GetUserId())
		switch {
		case err == nil:
			pm.Domain = res.GetDomainId()
		default:
			// If domain is disabled , then this authorization will fail for all non-admin domain users
			if _, err := svc.authorize(ctx, "", auth.UserType, auth.UsersKind, res.GetId(), auth.MembershipPermission, auth.DomainType, res.GetDomainId()); err != nil {
				return mgclients.ClientsPage{}, err
			}
			ids, err = svc.listClientIDs(ctx, res.GetId(), pm.Permission)
			if err != nil {
				return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrNotFound, err)
			}
		}
	}

	pm.IDs = ids

	tp, err := svc.clients.RetrieveAllByIDs(ctx, pm)
	if err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	if showFullData != "true" {
		// 过滤 Client 字段
		for i := range tp.Clients {
			tp.Clients[i] = filterClientFields(tp.Clients[i])
		}
	}

	if pm.ListPerms && len(tp.Clients) > 0 {
		g, ctx := errgroup.WithContext(ctx)

		for i := range tp.Clients {
			// Copying loop variable "i" to avoid "loop variable captured by func literal"
			iter := i
			g.Go(func() error {
				return svc.retrievePermissions(ctx, res.GetId(), &tp.Clients[iter])
			})
		}

		if err := g.Wait(); err != nil {
			return mgclients.ClientsPage{}, err
		}
	}
	return tp, nil
}

func filterClientFields(client mgclients.Client) mgclients.Client {
	// 创建一个新的 Client 对象以存储过滤后的字段
	filteredClient := mgclients.Client{
		ID:          client.ID,
		Name:        client.Name,
		Credentials: client.Credentials,
		CreatedAt:   client.CreatedAt,
		UpdatedAt:   client.UpdatedAt,
		UpdatedBy:   client.UpdatedBy,
		Status:      client.Status,
		Role:        client.Role,
		Permissions: client.Permissions,
		Domain:      client.Domain,
		Metadata:    make(map[string]interface{}), // 初始化 Metadata
	}

	// 只有在字段存在时，才将其复制
	if val, exists := client.Metadata["aliase"]; exists {
		filteredClient.Metadata["aliase"] = val
	}
	if val, exists := client.Metadata["info"]; exists {
		filteredClient.Metadata["info"] = val
	}
	if val, exists := client.Metadata["is_channel"]; exists {
		filteredClient.Metadata["is_channel"] = val
	}
	if val, exists := client.Metadata["is_online"]; exists {
		filteredClient.Metadata["is_online"] = val
	}
	if val, exists := client.Metadata["out_channel"]; exists {
		filteredClient.Metadata["out_channel"] = val
	}
	if val, exists := client.Metadata["out_channel_array"]; exists {
		filteredClient.Metadata["out_channel_array"] = val
	}
	if val, exists := client.Metadata["product_name"]; exists {
		filteredClient.Metadata["product_name"] = val
	}

	filteredClient.Metadata["test"] = "test_attribute"
	return filteredClient
}

// Experimental functions used for async calling of svc.listUserThingPermission. This might be helpful during listing of large number of entities.
func (svc service) retrievePermissions(ctx context.Context, userID string, client *mgclients.Client) error {
	permissions, err := svc.listUserThingPermission(ctx, userID, client.ID)
	if err != nil {
		return err
	}
	client.Permissions = permissions
	return nil
}

func (svc service) listUserThingPermission(ctx context.Context, userID, thingID string) ([]string, error) {
	lp, err := svc.auth.ListPermissions(ctx, &magistrala.ListPermissionsReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Object:      thingID,
		ObjectType:  auth.ThingType,
	})
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	return lp.GetPermissions(), nil
}

func (svc service) listClientIDs(ctx context.Context, userID, permission string) ([]string, error) {
	tids, err := svc.auth.ListAllObjects(ctx, &magistrala.ListObjectsReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Permission:  permission,
		ObjectType:  auth.ThingType,
	})
	if err != nil {
		return nil, errors.Wrap(repoerr.ErrNotFound, err)
	}
	return tids.Policies, nil
}

func (svc service) filterAllowedThingIDs(ctx context.Context, userID, permission string, thingIDs []string) ([]string, error) {
	var ids []string
	tids, err := svc.auth.ListAllObjects(ctx, &magistrala.ListObjectsReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Permission:  permission,
		ObjectType:  auth.ThingType,
	})
	if err != nil {
		return nil, errors.Wrap(repoerr.ErrNotFound, err)
	}
	for _, thingID := range thingIDs {
		for _, tid := range tids.Policies {
			if thingID == tid {
				ids = append(ids, thingID)
			}
		}
	}
	return ids, nil
}

func (svc service) checkSuperAdmin(ctx context.Context, userID string) error {
	res, err := svc.auth.Authorize(ctx, &magistrala.AuthorizeReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Permission:  auth.AdminPermission,
		ObjectType:  auth.PlatformType,
		Object:      auth.MagistralaObject,
	})
	if err != nil {
		return err
	}
	if !res.Authorized {
		return svcerr.ErrAuthorization
	}
	return nil
}

func (svc service) UpdateClient(ctx context.Context, token string, cli mgclients.Client) (mgclients.Client, error) {
	userID, err := svc.authorize(ctx, "", auth.UserType, auth.TokenKind, token, auth.EditPermission, auth.ThingType, cli.ID)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

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

	cRepo := postgres.NewRepository(database)
	oldThing, _ := cRepo.RetrieveByIdentity(ctx, cli.Credentials.Identity)
	onlineStatus, statusOk := oldThing.Metadata["online_status"].(string)

	client := mgclients.Client{
		ID:        cli.ID,
		Name:      cli.Name,
		Metadata:  cli.Metadata,
		UpdatedAt: time.Now(),
		UpdatedBy: userID,
	}
	if statusOk {
		client.Metadata["online_status"] = onlineStatus
	}
	client, err = svc.clients.Update(ctx, client)
	if err != nil {
		fmt.Println("UpdateClient Error: ", err)
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	// out_channel 大于1, 且is_channel等于0时，说明是多通道设备，需要把多通道都同时修改name、aliase
	if outChannel, ok := client.Metadata["out_channel"].(string); ok {
		fmt.Println("thing is_channel 2345:", outChannel)
		// 转换为整数
		outChannelNum, _ := strconv.Atoi(outChannel)
		if outChannelNum > 1 {
			// 根据 out_channel 生成多个通道设备
			if outChannelArray, ok := client.Metadata["out_channel_array"].([]interface{}); ok {
				for i := 2; i <= len(outChannelArray); i++ {
					thing, err := cRepo.RetrieveByIdentity(ctx, client.Credentials.Identity+"_"+strconv.Itoa(i))
					if err != nil {
						fmt.Println("RetrieveByIdentity Error: ", err)
						continue // 如果检索失败，继续下一个循环
					}
					// 类型断言
					info, ok := client.Metadata["info"].(map[string]interface{})
					if !ok {
						fmt.Println("Invalid type for Metadata['info']")
						continue
					}

					thing.Metadata["info"] = deepcopy.Copy(info).(map[string]interface{})
					// 处理 out_channel
					if outChannelData, ok := info["out_channel"].(map[string]interface{}); ok {
						if channels, ok := outChannelData["channel"].([]interface{}); ok {
							if len(channels) > 0 {
								if i-1 < len(channels) {
									channelInfo, ok := channels[i-1].(map[string]interface{})
									if ok {
										if aliase, exists := channelInfo["aliase"].(string); exists {
											thing.Metadata["aliase"] = client.Name + "_" + aliase
											thing.Name = client.Name + "_" + aliase
										}
									}
								}
								thing.Metadata["out_channel_array"] = deepcopy.Copy(channels).([]interface{})
							}
							thing.Metadata["out_channel"] = strconv.Itoa(len(channels))
						}
					}
					thing.UpdatedAt = time.Now()
					_, err = cRepo.Update(ctx, thing)
					// _, err = svc.UpdateClient(ctx, token, thing)
					if err != nil {
						fmt.Println("UpdateClient thingName 1234: ", thing.Name)
						fmt.Println("UpdateClient Error 1234: ", err)
					}
				}
			}
		}
	}
	return client, nil
}

func (svc service) UpdateClientTags(ctx context.Context, token string, cli mgclients.Client) (mgclients.Client, error) {
	userID, err := svc.authorize(ctx, "", auth.UserType, auth.TokenKind, token, auth.EditPermission, auth.ThingType, cli.ID)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	client := mgclients.Client{
		ID:        cli.ID,
		Tags:      cli.Tags,
		UpdatedAt: time.Now(),
		UpdatedBy: userID,
	}
	client, err = svc.clients.UpdateTags(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return client, nil
}

func (svc service) UpdateClientSecret(ctx context.Context, token, id, key string) (mgclients.Client, error) {
	userID, err := svc.authorize(ctx, "", auth.UserType, auth.TokenKind, token, auth.EditPermission, auth.ThingType, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	client := mgclients.Client{
		ID: id,
		Credentials: mgclients.Credentials{
			Secret: key,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: userID,
		Status:    mgclients.EnabledStatus,
	}
	client, err = svc.clients.UpdateSecret(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return client, nil
}

func (svc service) EnableClient(ctx context.Context, token, id string) (mgclients.Client, error) {
	client := mgclients.Client{
		ID:        id,
		Status:    mgclients.EnabledStatus,
		UpdatedAt: time.Now(),
	}
	client, err := svc.changeClientStatus(ctx, token, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(mgclients.ErrEnableClient, err)
	}

	return client, nil
}

func (svc service) DisableClient(ctx context.Context, token, id string) (mgclients.Client, error) {
	client := mgclients.Client{
		ID:        id,
		Status:    mgclients.DisabledStatus,
		UpdatedAt: time.Now(),
	}
	client, err := svc.changeClientStatus(ctx, token, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(mgclients.ErrDisableClient, err)
	}

	if err := svc.clientCache.Remove(ctx, client.ID); err != nil {
		return client, errors.Wrap(repoerr.ErrRemoveEntity, err)
	}

	return client, nil
}

func (svc service) Share(ctx context.Context, token, id, relation string, userids ...string) error {
	user, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if _, err := svc.authorize(ctx, user.GetDomainId(), auth.UserType, auth.UsersKind, user.GetId(), auth.DeletePermission, auth.ThingType, id); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	policies := magistrala.AddPoliciesReq{}
	for _, userid := range userids {
		policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
			SubjectType: auth.UserType,
			Subject:     auth.EncodeDomainUserID(user.GetDomainId(), userid),
			Relation:    relation,
			ObjectType:  auth.ThingType,
			Object:      id,
		})
	}
	res, err := svc.auth.AddPolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(errAddPolicies, err)
	}
	if !res.Added {
		return err
	}
	return nil
}

func (svc service) Unshare(ctx context.Context, token, id, relation string, userids ...string) error {
	user, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if _, err := svc.authorize(ctx, user.GetDomainId(), auth.UserType, auth.UsersKind, user.GetId(), auth.DeletePermission, auth.ThingType, id); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	policies := magistrala.DeletePoliciesReq{}
	for _, userid := range userids {
		policies.DeletePoliciesReq = append(policies.DeletePoliciesReq, &magistrala.DeletePolicyReq{
			SubjectType: auth.UserType,
			Subject:     auth.EncodeDomainUserID(user.GetDomainId(), userid),
			Relation:    relation,
			ObjectType:  auth.ThingType,
			Object:      id,
		})
	}
	res, err := svc.auth.DeletePolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(errRemovePolicies, err)
	}
	if !res.Deleted {
		return err
	}
	return nil
}

func (svc service) DeleteClient(ctx context.Context, token, id string) error {
	res, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if _, err := svc.authorize(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), auth.DeletePermission, auth.ThingType, id); err != nil {
		return err
	}

	client, _ := svc.ViewClient(ctx, token, id)
	if client.ID != "" {
		outChannelStr, ok := client.Metadata["out_channel"].(string)
		fmt.Println("delete outChannel 1234: ", outChannelStr)
		if ok {
			outChannelInt, err := strconv.Atoi(outChannelStr)
			if err != nil {
				fmt.Println("Failed to convert out_channel to int:", err)
			} else {
				if outChannelInt > 1 {
					is_channel, ok := client.Metadata["is_channel"].(string)
					fmt.Println("delete is_channel 1234: ", is_channel)
					if ok {
						if is_channel == "0" {
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

							cRepo := postgres.NewRepository(database)
							for i := 2; i <= outChannelInt; i++ {
								fmt.Println("delete newThing identity:", client.Credentials.Identity+"_"+strconv.Itoa(i))
								newThing, _ := cRepo.RetrieveByIdentity(ctx, client.Credentials.Identity+"_"+strconv.Itoa(i))
								fmt.Println("delete newThing:", newThing.ID)
								if newThing.ID != "" {
									_ = svc.DeleteClient(ctx, token, newThing.ID)
								}
							}
						}
					}
				}
			}
		}
	}

	// Remove from cache
	if err := svc.clientCache.Remove(ctx, id); err != nil {
		return errors.Wrap(repoerr.ErrRemoveEntity, err)
	}

	// Remove policy of groups
	if _, err := svc.auth.DeletePolicy(ctx, &magistrala.DeletePolicyReq{
		SubjectType: auth.GroupType,
		Object:      id,
		ObjectType:  auth.ThingType,
	}); err != nil {
		return err
	}

	// Remove policy from domain
	if _, err := svc.auth.DeletePolicy(ctx, &magistrala.DeletePolicyReq{
		SubjectType: auth.DomainType,
		Object:      id,
		ObjectType:  auth.ThingType,
	}); err != nil {
		return err
	}

	// Remove thing from database
	if err := svc.clients.Delete(ctx, id); err != nil {
		return err
	}

	// Remove policy of users
	if _, err := svc.auth.DeletePolicy(ctx, &magistrala.DeletePolicyReq{
		SubjectType: auth.UserType,
		Object:      id,
		ObjectType:  auth.ThingType,
	}); err != nil {
		return err
	}

	return nil
}

func (svc service) changeClientStatus(ctx context.Context, token string, client mgclients.Client) (mgclients.Client, error) {
	userID, err := svc.authorize(ctx, "", auth.UserType, auth.TokenKind, token, auth.DeletePermission, auth.ThingType, client.ID)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	dbClient, err := svc.clients.RetrieveByID(ctx, client.ID)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrViewEntity, err)
	}
	if dbClient.Status == client.Status {
		return mgclients.Client{}, errors.ErrStatusAlreadyAssigned
	}

	client.UpdatedBy = userID

	client, err = svc.clients.ChangeStatus(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return client, nil
}

func (svc service) ListClientsByGroup(ctx context.Context, token, groupID string, pm mgclients.Page) (mgclients.MembersPage, error) {
	res, err := svc.identify(ctx, token)
	if err != nil {
		return mgclients.MembersPage{}, err
	}
	if _, err := svc.authorize(ctx, res.GetDomainId(), auth.UserType, auth.UsersKind, res.GetId(), pm.Permission, auth.GroupType, groupID); err != nil {
		return mgclients.MembersPage{}, err
	}

	tids, err := svc.auth.ListAllObjects(ctx, &magistrala.ListObjectsReq{
		SubjectType: auth.GroupType,
		Subject:     groupID,
		Permission:  auth.GroupRelation,
		ObjectType:  auth.ThingType,
	})
	if err != nil {
		return mgclients.MembersPage{}, errors.Wrap(repoerr.ErrNotFound, err)
	}

	pm.IDs = tids.Policies

	cp, err := svc.clients.RetrieveAllByIDs(ctx, pm)
	if err != nil {
		return mgclients.MembersPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	if pm.ListPerms && len(cp.Clients) > 0 {
		g, ctx := errgroup.WithContext(ctx)

		for i := range cp.Clients {
			// Copying loop variable "i" to avoid "loop variable captured by func literal"
			iter := i
			g.Go(func() error {
				return svc.retrievePermissions(ctx, res.GetId(), &cp.Clients[iter])
			})
		}

		if err := g.Wait(); err != nil {
			return mgclients.MembersPage{}, err
		}
	}

	return mgclients.MembersPage{
		Page:    cp.Page,
		Members: cp.Clients,
	}, nil
}

func (svc service) Identify(ctx context.Context, key string) (string, error) {
	id, err := svc.clientCache.ID(ctx, key)
	if err == nil {
		return id, nil
	}

	client, err := svc.clients.RetrieveBySecret(ctx, key)
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if err := svc.clientCache.Save(ctx, key, client.ID); err != nil {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return client.ID, nil
}

func (svc service) identify(ctx context.Context, token string) (*magistrala.IdentityRes, error) {
	res, err := svc.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return nil, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if res.GetId() == "" || res.GetDomainId() == "" {
		return nil, svcerr.ErrDomainAuthorization
	}
	return res, nil
}

func (svc *service) authorize(ctx context.Context, domainID, subjType, subjKind, subj, perm, objType, obj string) (string, error) {
	req := &magistrala.AuthorizeReq{
		Domain:      domainID,
		SubjectType: subjType,
		SubjectKind: subjKind,
		Subject:     subj,
		Permission:  perm,
		ObjectType:  objType,
		Object:      obj,
	}
	res, err := svc.auth.Authorize(ctx, req)
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return res.GetId(), nil
}
