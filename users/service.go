// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/auth"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgoauth2 "github.com/absmach/magistrala/pkg/oauth2"
	"github.com/absmach/magistrala/users/postgres"
	"github.com/go-redis/redis/v8"
	"golang.org/x/sync/errgroup"
)

type service struct {
	clients      postgres.Repository
	idProvider   magistrala.IDProvider
	auth         magistrala.AuthServiceClient
	hasher       Hasher
	email        Emailer
	selfRegister bool
}

type TokenResponseBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccessType   string `json:"access_type"`
}

type UserInfo struct {
	Identity string
	Secret   string
}

// Credentials 结构体表示credentials对象
type Credentials struct {
	Identity string `json:"identity"`
}

// UserInfo 结构体表示整个JSON对象
type UserInfoResponseBody struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Credentials Credentials            `json:"credentials"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	UpdatedBy   string                 `json:"updated_by"`
	Status      string                 `json:"status"`
}

var encryptedKey = []byte(`LFJEW2HvOI9EpI5FmIWE*#&$(HFKDFR0`)
var CurrentUser = UserInfo{}

// NewService returns a new Users service implementation.
func NewService(crepo postgres.Repository, authClient magistrala.AuthServiceClient, emailer Emailer, hasher Hasher, idp magistrala.IDProvider, selfRegister bool) Service {
	return service{
		clients:      crepo,
		auth:         authClient,
		hasher:       hasher,
		email:        emailer,
		idProvider:   idp,
		selfRegister: selfRegister,
	}
}

// pkcs7UnPadding 移除PKCS#7填充
func pkcs7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	fmt.Println("origData: ", origData)

	if length == 0 {
		return nil, fmt.Errorf("input data is empty")
	}
	padding := int(origData[length-1])
	fmt.Println("padding: ", padding)
	fmt.Println("length: ", length)
	fmt.Println("aes.BlockSize: ", aes.BlockSize)

	if padding > length || padding > aes.BlockSize {
		return nil, fmt.Errorf("padding size error")
	}
	return origData[:length-padding], nil
}

// 密码解密
// Decrypts text from base64 encoded string using AES-CBC mode and removes PKCS#7 padding
func decrypt(encryptedString string, key []byte) (string, error) {
	if strings.Contains(encryptedString, ":") {
		//如果包含:则将字符串用:分割，进行解密
		parts := strings.Split(encryptedString, ":")
		ciphertext, _ := base64.StdEncoding.DecodeString(parts[0])
		iv, _ := base64.StdEncoding.DecodeString(parts[1])
		// 创建一个新的 cipher.Block
		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
		// 创建一个新的 CBC BlockMode
		if len(ciphertext) < aes.BlockSize {
			fmt.Println("ciphertext too short")
			return "", err
		}
		if len(ciphertext)%aes.BlockSize != 0 {
			fmt.Println("ciphertext is not a multiple of the block size")
			return "", err
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		// 创建一个字节切片来存储解密后的数据
		mode.CryptBlocks(ciphertext, ciphertext)
		decrypted, err := pkcs7UnPadding(ciphertext)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	} else {
		//如果不包含:则原样返回
		return encryptedString, nil
	}
}

func httpGetToken(identity string, secret string) (*TokenResponseBody, error) {
	// 用已创建的用户获取新token
	postData := []byte(`{"identity":"` + identity + `","secret":"` + secret + `"}`)
	url := "http://users:9002/users/tokens/issue"
	// 创建请求
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println("Response Status1:", resp.Status)
	fmt.Println("Response Body1:", string(body))
	var tokenResponseBody TokenResponseBody
	err = json.Unmarshal(body, &tokenResponseBody)
	if err != nil {
		return nil, err
	}

	CurrentUser.Identity = identity
	CurrentUser.Secret = secret
	// 连接到Redis服务器
	rdb := redis.NewClient(&redis.Options{
		Addr:     "things-redis:6379", // Redis服务器地址和端口
		Password: "",                  // Redis密码（如果有的话）
		DB:       0,                   // Redis数据库索引（默认为0）
	})
	rdctx := context.Background()
	_, err = rdb.Ping(rdctx).Result()
	if err != nil {
		fmt.Printf("无法连接到Redis: %v", err)
	} else {
		err = rdb.Set(rdctx, "CurrentUserIdentity", CurrentUser.Identity, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
		err = rdb.Set(rdctx, "CurrentUserSecret", CurrentUser.Secret, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
	}

	return &tokenResponseBody, nil
}

// 使用token获取用户信息
func httpGetUserInfo(token string) (UserInfoResponseBody, error) {
	// 用已创建的用户获取新token
	url := "http://users:9002/users/profile"
	// 创建请求
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Println("err httpGetUserInfo 1111: ", err)
		return UserInfoResponseBody{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("err httpGetUserInfo 2222: ", err)
		return UserInfoResponseBody{}, err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("err httpGetUserInfo 333: ", err)
		return UserInfoResponseBody{}, err
	}
	fmt.Println("Response Status UserInfo:", resp.Status)
	fmt.Println("Response Body UserInfo:", string(body))
	var userInfoResponseBody UserInfoResponseBody
	err = json.Unmarshal(body, &userInfoResponseBody)
	if err != nil {
		fmt.Println("err httpGetUserInfo 444: ", err)
		return UserInfoResponseBody{}, err
	}

	return userInfoResponseBody, nil
}

// 创建默认domain
func createDefaultDomain(token string) (auth.Domain, error) {
	// 创建用户默认创建一个domain
	// 要发送的数据
	var domain auth.Domain
	postData := []byte(`{
			"name": "默认机构",
			"tags": [],
			"metadata": {},
			"alias": "默认机构"
		}`)
	url := "http://auth:8189/domains"
	// 创建请求
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postData))
	if err != nil {
		return auth.Domain{}, err
	}
	// 设置Header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return auth.Domain{}, err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return auth.Domain{}, err
	}
	// 解析JSON字符串到User结构体
	_ = json.Unmarshal(body, &domain)
	return domain, err
}

func (svc service) RegisterClient(ctx context.Context, token string, cli mgclients.Client) (rc mgclients.Client, err error) {
	secret := cli.Credentials.Secret
	if !svc.selfRegister {
		userID, err := svc.Identify(ctx, token)
		if err != nil {
			fmt.Println("RegisterClient 11: ", err)
			return mgclients.Client{}, err
		}
		if err := svc.checkSuperAdmin(ctx, userID); err != nil {
			fmt.Println("RegisterClient 22: ", err)
			return mgclients.Client{}, err
		}
	}

	clientID, err := svc.idProvider.ID()
	if err != nil {
		fmt.Println("RegisterClient 33: ", err)
		return mgclients.Client{}, err
	}

	if cli.Credentials.Secret != "" {
		// 密码解密
		secret := cli.Credentials.Secret
		secret, _ = decrypt(secret, encryptedKey)
		hash, err := svc.hasher.Hash(secret)
		if err != nil {
			fmt.Println("RegisterClient 44: ", err)
			return mgclients.Client{}, errors.Wrap(repoerr.ErrMalformedEntity, err)
		}
		cli.Credentials.Secret = hash
	}

	if cli.Status != mgclients.DisabledStatus && cli.Status != mgclients.EnabledStatus {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrInvalidStatus)
	}
	if cli.Role != mgclients.UserRole && cli.Role != mgclients.AdminRole {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrInvalidRole)
	}
	cli.ID = clientID
	cli.CreatedAt = time.Now()

	if err := svc.addClientPolicy(ctx, cli.ID, cli.Role); err != nil {
		fmt.Println("RegisterClient 55: ", err)
		return mgclients.Client{}, err
	}
	defer func() {
		if err != nil {
			if errRollback := svc.addClientPolicyRollback(ctx, cli.ID, cli.Role); errRollback != nil {
				fmt.Println("RegisterClient 66: ", err)
				err = errors.Wrap(errors.Wrap(repoerr.ErrRollbackTx, errRollback), err)
			}
		}
	}()
	client, err := svc.clients.Save(ctx, cli)
	if err != nil {
		fmt.Println("RegisterClient 77: ", err)
		return mgclients.Client{}, errors.Wrap(repoerr.ErrCreateEntity, err)
	}

	//通过新建的用户获取token
	tokenResponseBody, err := httpGetToken(client.Credentials.Identity, secret)
	if err != nil {
		fmt.Printf("Failed to call the first API: %v\n", err)
		return client, nil
	}
	newToken := tokenResponseBody.AccessToken

	//创建默认domain
	domain, err := createDefaultDomain(newToken)
	if err != nil {
		fmt.Printf("Failed to call the second API: %v\n", err)
		return client, nil
	}

	//创建默认domain之后默认将这个domainID写入用户信息的metadata中
	if domain.ID != "" {
		//获取最新的user最新的metata，再更新domainID
		userInfo, _ := httpGetUserInfo(newToken)
		jsonData, _ := json.Marshal(userInfo)
		fmt.Println("userService userinfo data: ", string(jsonData))
		userInfo.Metadata["domainID"] = domain.ID
		client.Metadata = userInfo.Metadata
		client.UpdatedAt = time.Now()
		client.UpdatedBy = client.ID
		client, _ = svc.clients.Update(ctx, client)
	}
	return client, nil
}

func (svc service) IssueToken(ctx context.Context, identity, secretStr, domainID string) (*magistrala.Token, error) {
	dbUser, err := svc.clients.RetrieveByIdentity(ctx, identity)
	if err != nil {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	// 密码解密
	secret, _ := decrypt(secretStr, encryptedKey)
	var sercetVar string = secret
	if err := svc.hasher.Compare(secret, dbUser.Credentials.Secret); err != nil {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrLogin, err)
	}

	var d string
	if domainID != "" {
		d = domainID
	}

	CurrentUser.Identity = identity
	CurrentUser.Secret = sercetVar
	// 连接到Redis服务器
	rdb := redis.NewClient(&redis.Options{
		Addr:     "things-redis:6379", // Redis服务器地址和端口
		Password: "",                  // Redis密码（如果有的话）
		DB:       0,                   // Redis数据库索引（默认为0）
	})
	rdctx := context.Background()
	_, err = rdb.Ping(rdctx).Result()
	if err != nil {
		fmt.Printf("无法连接到Redis: %v", err)
	} else {
		err = rdb.Set(rdctx, "CurrentUserIdentity", CurrentUser.Identity, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
		err = rdb.Set(rdctx, "CurrentUserSecret", CurrentUser.Secret, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
	}

	return svc.auth.Issue(ctx, &magistrala.IssueReq{UserId: dbUser.ID, DomainId: &d, Type: uint32(auth.AccessKey)})
}

func (svc service) RefreshToken(ctx context.Context, refreshToken, domainID string) (*magistrala.Token, error) {
	var d string
	if domainID != "" {
		d = domainID
	}
	return svc.auth.Refresh(ctx, &magistrala.RefreshReq{RefreshToken: refreshToken, DomainId: &d})
}

func (svc service) ViewClient(ctx context.Context, token, id string) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}

	if tokenUserID != id {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return mgclients.Client{}, err
		}
	}

	client, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	client.Credentials.Secret = ""

	return client, nil
}

func (svc service) ViewProfile(ctx context.Context, token string) (mgclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}
	client, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	client.Credentials.Secret = ""

	return client, nil
}

func (svc service) ListClients(ctx context.Context, token string, pm mgclients.Page) (mgclients.ClientsPage, error) {
	userID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.ClientsPage{}, err
	}
	if err := svc.checkSuperAdmin(ctx, userID); err == nil {
		pg, err := svc.clients.RetrieveAll(ctx, pm)
		if err != nil {
			return mgclients.ClientsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
		}
		return pg, err
	}

	p := mgclients.Page{
		Status:   mgclients.EnabledStatus,
		Offset:   pm.Offset,
		Limit:    pm.Limit,
		Name:     pm.Name,
		Identity: pm.Identity,
		Role:     mgclients.UserRole,
	}
	pg, err := svc.clients.RetrieveAll(ctx, p)
	if err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return pg, nil
}

func (svc service) UpdateClient(ctx context.Context, token string, cli mgclients.Client) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}

	if tokenUserID != cli.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return mgclients.Client{}, err
		}
	}

	client := mgclients.Client{
		ID:        cli.ID,
		Name:      cli.Name,
		Metadata:  cli.Metadata,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}

	client, err = svc.clients.Update(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return client, nil
}

func (svc service) UpdateClientTags(ctx context.Context, token string, cli mgclients.Client) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}

	if tokenUserID != cli.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return mgclients.Client{}, err
		}
	}

	client := mgclients.Client{
		ID:        cli.ID,
		Tags:      cli.Tags,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}
	client, err = svc.clients.UpdateTags(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	return client, nil
}

func (svc service) UpdateClientIdentity(ctx context.Context, token, clientID, identity string) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}

	if tokenUserID != clientID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return mgclients.Client{}, err
		}
	}

	cli := mgclients.Client{
		ID: clientID,
		Credentials: mgclients.Credentials{
			Identity: identity,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}
	cli, err = svc.clients.UpdateIdentity(ctx, cli)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	CurrentUser.Identity = identity
	// 连接到Redis服务器
	rdb := redis.NewClient(&redis.Options{
		Addr:     "things-redis:6379", // Redis服务器地址和端口
		Password: "",                  // Redis密码（如果有的话）
		DB:       0,                   // Redis数据库索引（默认为0）
	})
	rdctx := context.Background()
	_, err = rdb.Ping(rdctx).Result()
	if err != nil {
		fmt.Printf("无法连接到Redis: %v", err)
	} else {
		err = rdb.Set(rdctx, "CurrentUserIdentity", CurrentUser.Identity, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
	}

	return cli, nil
}

func (svc service) GenerateResetToken(ctx context.Context, email, host string) error {
	client, err := svc.clients.RetrieveByIdentity(ctx, email)
	if err != nil || client.Credentials.Identity == "" {
		return repoerr.ErrNotFound
	}
	issueReq := &magistrala.IssueReq{
		UserId: client.ID,
		Type:   uint32(auth.RecoveryKey),
	}
	token, err := svc.auth.Issue(ctx, issueReq)
	if err != nil {
		return errors.Wrap(svcerr.ErrRecoveryToken, err)
	}

	return svc.SendPasswordReset(ctx, host, email, client.Name, token.AccessToken)
}

func (svc service) ResetSecret(ctx context.Context, resetToken, secretStr string) error {
	id, err := svc.Identify(ctx, resetToken)
	if err != nil {
		return err
	}
	c, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return errors.Wrap(svcerr.ErrViewEntity, err)
	}
	if c.Credentials.Identity == "" {
		return repoerr.ErrNotFound
	}
	// 密码解密
	secret, _ := decrypt(secretStr, encryptedKey)
	var sercetVar string = secret
	secret, err = svc.hasher.Hash(secret)
	if err != nil {
		return err
	}
	c = mgclients.Client{
		ID: c.ID,
		Credentials: mgclients.Credentials{
			Identity: c.Credentials.Identity,
			Secret:   secret,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}
	if _, err := svc.clients.UpdateSecret(ctx, c); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	CurrentUser.Secret = sercetVar
	// 连接到Redis服务器
	rdb := redis.NewClient(&redis.Options{
		Addr:     "things-redis:6379", // Redis服务器地址和端口
		Password: "",                  // Redis密码（如果有的话）
		DB:       0,                   // Redis数据库索引（默认为0）
	})
	rdctx := context.Background()
	_, err = rdb.Ping(rdctx).Result()
	if err != nil {
		fmt.Printf("无法连接到Redis: %v", err)
	} else {
		err = rdb.Set(rdctx, "CurrentUserSecret", CurrentUser.Secret, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
	}

	return nil
}

func (svc service) UpdateClientSecret(ctx context.Context, token, oldSecretStr, newSecretStr string) (mgclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}
	dbClient, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	// 密码解密
	oldSecret, _ := decrypt(oldSecretStr, encryptedKey)
	newSecret, _ := decrypt(newSecretStr, encryptedKey)
	if _, err := svc.IssueToken(ctx, dbClient.Credentials.Identity, oldSecret, ""); err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrIssueToken, err)
	}
	var sercetVar string = newSecret
	newSecret, err = svc.hasher.Hash(newSecret)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrMalformedEntity, err)
	}
	dbClient.Credentials.Secret = newSecret
	dbClient.UpdatedAt = time.Now()
	dbClient.UpdatedBy = id

	dbClient, err = svc.clients.UpdateSecret(ctx, dbClient)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	CurrentUser.Secret = sercetVar
	// 连接到Redis服务器
	rdb := redis.NewClient(&redis.Options{
		Addr:     "things-redis:6379", // Redis服务器地址和端口
		Password: "",                  // Redis密码（如果有的话）
		DB:       0,                   // Redis数据库索引（默认为0）
	})
	rdctx := context.Background()
	_, err = rdb.Ping(rdctx).Result()
	if err != nil {
		fmt.Printf("无法连接到Redis: %v", err)
	} else {
		err = rdb.Set(rdctx, "CurrentUserSecret", CurrentUser.Secret, 1*365*24*time.Hour).Err()
		if err != nil {
			fmt.Printf("Failed to set value in Redis: %v\n", err)
		}
	}

	return dbClient, nil
}

func (svc service) SendPasswordReset(_ context.Context, host, email, user, token string) error {
	to := []string{email}
	return svc.email.SendPasswordReset(to, host, user, token)
}

func (svc service) UpdateClientRole(ctx context.Context, token string, cli mgclients.Client) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}

	if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
		return mgclients.Client{}, err
	}
	client := mgclients.Client{
		ID:        cli.ID,
		Role:      cli.Role,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}

	if err := svc.updateClientPolicy(ctx, cli.ID, cli.Role); err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrFailedPolicyUpdate, err)
	}
	client, err = svc.clients.UpdateRole(ctx, client)
	if err != nil {
		// If failed to update role in DB, then revert back to platform admin policy in spicedb
		if errRollback := svc.updateClientPolicy(ctx, cli.ID, mgclients.UserRole); errRollback != nil {
			return mgclients.Client{}, errors.Wrap(err, errors.Wrap(repoerr.ErrRollbackTx, errRollback))
		}
		return mgclients.Client{}, errors.Wrap(svcerr.ErrFailedUpdateRole, err)
	}
	return client, nil
}

func (svc service) EnableClient(ctx context.Context, token, id string) (mgclients.Client, error) {
	client := mgclients.Client{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mgclients.EnabledStatus,
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
		UpdatedAt: time.Now(),
		Status:    mgclients.DisabledStatus,
	}
	client, err := svc.changeClientStatus(ctx, token, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(mgclients.ErrDisableClient, err)
	}

	return client, nil
}

func (svc service) changeClientStatus(ctx context.Context, token string, client mgclients.Client) (mgclients.Client, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return mgclients.Client{}, err
	}
	if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
		return mgclients.Client{}, err
	}
	dbClient, err := svc.clients.RetrieveByID(ctx, client.ID)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	if dbClient.Status == client.Status {
		return mgclients.Client{}, errors.ErrStatusAlreadyAssigned
	}
	client.UpdatedBy = tokenUserID

	client, err = svc.clients.ChangeStatus(ctx, client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return client, err
}

func (svc service) ListMembers(ctx context.Context, token, objectKind, objectID string, pm mgclients.Page) (mgclients.MembersPage, error) {
	res, err := svc.identify(ctx, token)
	if err != nil {
		return mgclients.MembersPage{}, err
	}
	var objectType string
	var authzPerm string
	switch objectKind {
	case auth.ThingsKind:
		objectType = auth.ThingType
		authzPerm = pm.Permission
	case auth.DomainsKind:
		objectType = auth.DomainType
		authzPerm = auth.SwitchToPermission(pm.Permission)
	case auth.GroupsKind:
		fallthrough
	default:
		objectType = auth.GroupType
		authzPerm = auth.SwitchToPermission(pm.Permission)
	}

	if _, err := svc.authorize(ctx, auth.UserType, auth.TokenKind, token, authzPerm, objectType, objectID); err != nil {
		return mgclients.MembersPage{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	duids, err := svc.auth.ListAllSubjects(ctx, &magistrala.ListSubjectsReq{
		SubjectType: auth.UserType,
		Permission:  pm.Permission,
		Object:      objectID,
		ObjectType:  objectType,
	})
	if err != nil {
		return mgclients.MembersPage{}, errors.Wrap(svcerr.ErrNotFound, err)
	}
	if len(duids.Policies) == 0 {
		return mgclients.MembersPage{
			Page: mgclients.Page{Total: 0, Offset: pm.Offset, Limit: pm.Limit},
		}, nil
	}

	var userIDs []string

	for _, domainUserID := range duids.Policies {
		_, userID := auth.DecodeDomainUserID(domainUserID)
		userIDs = append(userIDs, userID)
	}
	pm.IDs = userIDs

	cp, err := svc.clients.RetrieveAll(ctx, pm)
	if err != nil {
		return mgclients.MembersPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	if pm.ListPerms && len(cp.Clients) > 0 {
		g, ctx := errgroup.WithContext(ctx)

		for i := range cp.Clients {
			// Copying loop variable "i" to avoid "loop variable captured by func literal"
			iter := i
			g.Go(func() error {
				return svc.retrieveObjectUsersPermissions(ctx, res.GetDomainId(), objectType, objectID, &cp.Clients[iter])
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

func (svc service) retrieveObjectUsersPermissions(ctx context.Context, domainID, objectType, objectID string, client *mgclients.Client) error {
	userID := auth.EncodeDomainUserID(domainID, client.ID)
	permissions, err := svc.listObjectUserPermission(ctx, userID, objectType, objectID)
	if err != nil {
		return err
	}
	client.Permissions = permissions
	return nil
}

func (svc service) listObjectUserPermission(ctx context.Context, userID, objectType, objectID string) ([]string, error) {
	lp, err := svc.auth.ListPermissions(ctx, &magistrala.ListPermissionsReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Object:      objectID,
		ObjectType:  objectType,
	})
	if err != nil {
		return []string{}, err
	}
	return lp.GetPermissions(), nil
}

func (svc *service) checkSuperAdmin(ctx context.Context, adminID string) error {
	if _, err := svc.authorize(ctx, auth.UserType, auth.UsersKind, adminID, auth.AdminPermission, auth.PlatformType, auth.MagistralaObject); err != nil {
		if err := svc.clients.CheckSuperAdmin(ctx, adminID); err != nil {
			return errors.Wrap(svcerr.ErrAuthorization, err)
		}
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return nil
}

func (svc service) identify(ctx context.Context, token string) (*magistrala.IdentityRes, error) {
	res, err := svc.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return &magistrala.IdentityRes{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	return res, nil
}

func (svc *service) authorize(ctx context.Context, subjType, subjKind, subj, perm, objType, obj string) (string, error) {
	req := &magistrala.AuthorizeReq{
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
		return "", svcerr.ErrAuthorization
	}
	return res.GetId(), nil
}

func (svc service) OAuthCallback(ctx context.Context, state mgoauth2.State, client mgclients.Client) (*magistrala.Token, error) {
	switch state {
	case mgoauth2.SignIn:
		rclient, err := svc.clients.RetrieveByIdentity(ctx, client.Credentials.Identity)
		if err != nil {
			if errors.Contains(err, repoerr.ErrNotFound) {
				return &magistrala.Token{}, errors.New("user not signed up")
			}
			return &magistrala.Token{}, err
		}
		claims := &magistrala.IssueReq{
			UserId: rclient.ID,
			Type:   uint32(auth.AccessKey),
		}
		return svc.auth.Issue(ctx, claims)
	case mgoauth2.SignUp:
		rclient, err := svc.RegisterClient(ctx, "", client)
		if err != nil {
			if errors.Contains(err, repoerr.ErrConflict) {
				return &magistrala.Token{}, errors.New("user already exists")
			}
			return &magistrala.Token{}, err
		}
		claims := &magistrala.IssueReq{
			UserId: rclient.ID,
			Type:   uint32(auth.AccessKey),
		}
		return svc.auth.Issue(ctx, claims)
	default:
		return &magistrala.Token{}, fmt.Errorf("unknown state %s", state)
	}
}

func (svc service) Identify(ctx context.Context, token string) (string, error) {
	user, err := svc.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthentication, err)
	}
	return user.GetUserId(), nil
}

func (svc service) addClientPolicy(ctx context.Context, userID string, role mgclients.Role) error {
	var policies magistrala.AddPoliciesReq

	policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Relation:    auth.MemberRelation,
		ObjectType:  auth.PlatformType,
		Object:      auth.MagistralaObject,
	})

	if role == mgclients.AdminRole {
		policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
	}
	resp, err := svc.auth.AddPolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(svcerr.ErrAddPolicies, err)
	}
	if !resp.Added {
		return svcerr.ErrAuthorization
	}
	return nil
}

func (svc service) addClientPolicyRollback(ctx context.Context, userID string, role mgclients.Role) error {
	var policies magistrala.DeletePoliciesReq

	policies.DeletePoliciesReq = append(policies.DeletePoliciesReq, &magistrala.DeletePolicyReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Relation:    auth.MemberRelation,
		ObjectType:  auth.PlatformType,
		Object:      auth.MagistralaObject,
	})

	if role == mgclients.AdminRole {
		policies.DeletePoliciesReq = append(policies.DeletePoliciesReq, &magistrala.DeletePolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
	}
	resp, err := svc.auth.DeletePolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(svcerr.ErrDeletePolicies, err)
	}
	if !resp.Deleted {
		return svcerr.ErrAuthorization
	}
	return nil
}

func (svc service) updateClientPolicy(ctx context.Context, userID string, role mgclients.Role) error {
	switch role {
	case mgclients.AdminRole:
		resp, err := svc.auth.AddPolicy(ctx, &magistrala.AddPolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
		if err != nil {
			return errors.Wrap(svcerr.ErrAddPolicies, err)
		}
		if !resp.Added {
			return svcerr.ErrAuthorization
		}
		return nil
	case mgclients.UserRole:
		fallthrough
	default:
		resp, err := svc.auth.DeletePolicy(ctx, &magistrala.DeletePolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
		if err != nil {
			return errors.Wrap(svcerr.ErrDeletePolicies, err)
		}
		if !resp.Deleted {
			return svcerr.ErrAuthorization
		}
		return nil
	}
}
