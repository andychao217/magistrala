// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andychao217/magistrala"
	mgclients "github.com/andychao217/magistrala/pkg/clients"
	"github.com/andychao217/magistrala/pkg/errors"
	svcerr "github.com/andychao217/magistrala/pkg/errors/service"
	"github.com/go-redis/redis/v8"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var minioClient *minio.Client

const (
	recoveryDuration = 5 * time.Minute
	defLimit         = 100
)

var (
	// ErrExpiry indicates that the token is expired.
	ErrExpiry = errors.New("token is expired")

	errIssueUser          = errors.New("failed to issue new login key")
	errIssueTmp           = errors.New("failed to issue new temporary key")
	errRevoke             = errors.New("failed to remove key")
	errRetrieve           = errors.New("failed to retrieve key data")
	errIdentify           = errors.New("failed to validate token")
	errPlatform           = errors.New("invalid platform id")
	errCreateDomainPolicy = errors.New("failed to create domain policy")
	errAddPolicies        = errors.New("failed to add policies")
	errRemovePolicies     = errors.New("failed to remove the policies")
	errRollbackPolicy     = errors.New("failed to rollback policy")
	errRemoveLocalPolicy  = errors.New("failed to remove from local policy copy")
	errRemovePolicyEngine = errors.New("failed to remove from policy engine")
	// errInvalidEntityType indicates invalid entity type.
	errInvalidEntityType = errors.New("invalid entity type")
)

// Authn specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
// Token is a string value of the actual Key and is used to authenticate
// an Auth service request.
type Authn interface {
	// Issue issues a new Key, returning its token value alongside.
	Issue(ctx context.Context, token string, key Key) (Token, error)

	// Revoke removes the Key with the provided id that is
	// issued by the user identified by the provided key.
	Revoke(ctx context.Context, token, id string) error

	// RetrieveKey retrieves data for the Key identified by the provided
	// ID, that is issued by the user identified by the provided key.
	RetrieveKey(ctx context.Context, token, id string) (Key, error)

	// Identify validates token token. If token is valid, content
	// is returned. If token is invalid, or invocation failed for some
	// other reason, non-nil error value is returned in response.
	Identify(ctx context.Context, token string) (Key, error)
}

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
// Token is a string value of the actual Key and is used to authenticate
// an Auth service request.

//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	Authn
	Authz
	Domains
}

var _ Service = (*service)(nil)

type service struct {
	keys               KeyRepository
	domains            DomainsRepository
	idProvider         magistrala.IDProvider
	agent              PolicyAgent
	tokenizer          Tokenizer
	loginDuration      time.Duration
	refreshDuration    time.Duration
	invitationDuration time.Duration
}

type TokenResponseBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccessType   string `json:"access_type"`
}

type Channel struct {
	ID        string `json:"id"`
	OwnerID   string `json:"owner_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Status    string `json:"status"`
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

// New instantiates the auth service implementation.
func New(keys KeyRepository, domains DomainsRepository, idp magistrala.IDProvider, tokenizer Tokenizer, policyAgent PolicyAgent, loginDuration, refreshDuration, invitationDuration time.Duration) Service {
	return &service{
		tokenizer:          tokenizer,
		domains:            domains,
		keys:               keys,
		idProvider:         idp,
		agent:              policyAgent,
		loginDuration:      loginDuration,
		refreshDuration:    refreshDuration,
		invitationDuration: invitationDuration,
	}
}

func (svc service) Issue(ctx context.Context, token string, key Key) (Token, error) {
	key.IssuedAt = time.Now().UTC()
	switch key.Type {
	case APIKey:
		return svc.userKey(ctx, token, key)
	case RefreshKey:
		return svc.refreshKey(ctx, token, key)
	case RecoveryKey:
		return svc.tmpKey(recoveryDuration, key)
	case InvitationKey:
		return svc.invitationKey(ctx, key)
	default:
		return svc.accessKey(ctx, key)
	}
}

func (svc service) Revoke(ctx context.Context, token, id string) error {
	issuerID, _, err := svc.authenticate(token)
	if err != nil {
		return errors.Wrap(errRevoke, err)
	}
	if err := svc.keys.Remove(ctx, issuerID, id); err != nil {
		return errors.Wrap(errRevoke, err)
	}
	return nil
}

func (svc service) RetrieveKey(ctx context.Context, token, id string) (Key, error) {
	issuerID, _, err := svc.authenticate(token)
	if err != nil {
		return Key{}, errors.Wrap(errRetrieve, err)
	}

	key, err := svc.keys.Retrieve(ctx, issuerID, id)
	if err != nil {
		return Key{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return key, nil
}

func (svc service) Identify(ctx context.Context, token string) (Key, error) {
	key, err := svc.tokenizer.Parse(token)
	if errors.Contains(err, ErrExpiry) {
		err = svc.keys.Remove(ctx, key.Issuer, key.ID)
		return Key{}, errors.Wrap(ErrKeyExpired, err)
	}
	if err != nil {
		return Key{}, errors.Wrap(svcerr.ErrAuthentication, errors.Wrap(errIdentify, err))
	}

	switch key.Type {
	case RecoveryKey, AccessKey, InvitationKey:
		return key, nil
	case APIKey:
		_, err := svc.keys.Retrieve(ctx, key.Issuer, key.ID)
		if err != nil {
			return Key{}, svcerr.ErrAuthentication
		}
		return key, nil
	default:
		return Key{}, svcerr.ErrAuthentication
	}
}

func (svc service) Authorize(ctx context.Context, pr PolicyReq) error {
	if err := svc.PolicyValidation(pr); err != nil {
		return errors.Wrap(svcerr.ErrMalformedEntity, err)
	}
	if pr.SubjectKind == TokenKind {
		key, err := svc.Identify(ctx, pr.Subject)
		if err != nil {
			return errors.Wrap(svcerr.ErrAuthentication, err)
		}
		if key.Subject == "" {
			if pr.ObjectType == GroupType || pr.ObjectType == ThingType || pr.ObjectType == DomainType {
				return svcerr.ErrDomainAuthorization
			}
			return svcerr.ErrAuthentication
		}
		pr.Subject = key.Subject
		pr.Domain = key.Domain
	}
	if err := svc.checkPolicy(ctx, pr); err != nil {
		return err
	}
	return nil
}

func (svc service) checkPolicy(ctx context.Context, pr PolicyReq) error {
	// Domain status is required for if user sent authorization request on things, channels, groups and domains
	if pr.SubjectType == UserType && (pr.ObjectType == GroupType || pr.ObjectType == ThingType || pr.ObjectType == DomainType) {
		domainID := pr.Domain
		if domainID == "" {
			if pr.ObjectType != DomainType {
				return svcerr.ErrDomainAuthorization
			}
			domainID = pr.Object
		}
		if err := svc.checkDomain(ctx, pr.SubjectType, pr.Subject, domainID); err != nil {
			return err
		}
	}
	if err := svc.agent.CheckPolicy(ctx, pr); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	return nil
}

func (svc service) checkDomain(ctx context.Context, subjectType, subject, domainID string) error {
	d, err := svc.domains.RetrieveByID(ctx, domainID)
	if err != nil {
		return errors.Wrap(svcerr.ErrViewEntity, err)
	}

	switch d.Status {
	case EnabledStatus:
	case DisabledStatus:
		if err := svc.agent.CheckPolicy(ctx, PolicyReq{
			Subject:     subject,
			SubjectType: subjectType,
			Permission:  AdminPermission,
			Object:      domainID,
			ObjectType:  DomainType,
		}); err != nil {
			return svcerr.ErrDomainAuthorization
		}
	case FreezeStatus:
		if err := svc.agent.CheckPolicy(ctx, PolicyReq{
			Subject:     subject,
			SubjectType: subjectType,
			Permission:  AdminPermission,
			Object:      MagistralaObject,
			ObjectType:  PlatformType,
		}); err != nil {
			return svcerr.ErrDomainAuthorization
		}
	default:
		return svcerr.ErrDomainAuthorization
	}

	return nil
}

func (svc service) AddPolicy(ctx context.Context, pr PolicyReq) error {
	if err := svc.PolicyValidation(pr); err != nil {
		return errors.Wrap(svcerr.ErrInvalidPolicy, err)
	}
	return svc.agent.AddPolicy(ctx, pr)
}

func (svc service) PolicyValidation(pr PolicyReq) error {
	if pr.ObjectType == PlatformType && pr.Object != MagistralaObject {
		return errPlatform
	}
	return nil
}

func (svc service) AddPolicies(ctx context.Context, prs []PolicyReq) error {
	for _, pr := range prs {
		if err := svc.PolicyValidation(pr); err != nil {
			return errors.Wrap(svcerr.ErrInvalidPolicy, err)
		}
	}
	return svc.agent.AddPolicies(ctx, prs)
}

func (svc service) DeletePolicyFilter(ctx context.Context, pr PolicyReq) error {
	return svc.agent.DeletePolicy(ctx, pr)
}

func (svc service) DeletePolicy(ctx context.Context, pr PolicyReq) error {
	return svc.agent.DeletePolicy(ctx, pr)
}

func (svc service) DeletePolicies(ctx context.Context, prs []PolicyReq) error {
	for _, pr := range prs {
		if err := svc.PolicyValidation(pr); err != nil {
			return errors.Wrap(svcerr.ErrInvalidPolicy, err)
		}
	}
	return svc.agent.DeletePolicies(ctx, prs)
}

func (svc service) ListObjects(ctx context.Context, pr PolicyReq, nextPageToken string, limit uint64) (PolicyPage, error) {
	if limit <= 0 {
		limit = 100
	}
	res, npt, err := svc.agent.RetrieveObjects(ctx, pr, nextPageToken, limit)
	if err != nil {
		return PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Object)
	}
	page.NextPageToken = npt
	return page, nil
}

func (svc service) ListAllObjects(ctx context.Context, pr PolicyReq) (PolicyPage, error) {
	res, err := svc.agent.RetrieveAllObjects(ctx, pr)
	if err != nil {
		return PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Object)
	}
	return page, nil
}

func (svc service) CountObjects(ctx context.Context, pr PolicyReq) (uint64, error) {
	return svc.agent.RetrieveAllObjectsCount(ctx, pr)
}

func (svc service) ListSubjects(ctx context.Context, pr PolicyReq, nextPageToken string, limit uint64) (PolicyPage, error) {
	if limit <= 0 {
		limit = 100
	}
	res, npt, err := svc.agent.RetrieveSubjects(ctx, pr, nextPageToken, limit)
	if err != nil {
		return PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Subject)
	}
	page.NextPageToken = npt
	return page, nil
}

func (svc service) ListAllSubjects(ctx context.Context, pr PolicyReq) (PolicyPage, error) {
	res, err := svc.agent.RetrieveAllSubjects(ctx, pr)
	if err != nil {
		return PolicyPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	var page PolicyPage
	for _, tuple := range res {
		page.Policies = append(page.Policies, tuple.Subject)
	}
	return page, nil
}

func (svc service) CountSubjects(ctx context.Context, pr PolicyReq) (uint64, error) {
	return svc.agent.RetrieveAllSubjectsCount(ctx, pr)
}

func (svc service) ListPermissions(ctx context.Context, pr PolicyReq, filterPermisions []string) (Permissions, error) {
	pers, err := svc.agent.RetrievePermissions(ctx, pr, filterPermisions)
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return pers, nil
}

func (svc service) tmpKey(duration time.Duration, key Key) (Token, error) {
	key.ExpiresAt = time.Now().Add(duration)
	value, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	return Token{AccessToken: value}, nil
}

func (svc service) accessKey(ctx context.Context, key Key) (Token, error) {
	var err error
	key.Type = AccessKey
	key.ExpiresAt = time.Now().Add(svc.loginDuration)

	key.Subject, err = svc.checkUserDomain(ctx, key)
	if err != nil {
		return Token{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	access, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	key.ExpiresAt = time.Now().Add(svc.refreshDuration)
	key.Type = RefreshKey
	refresh, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	return Token{AccessToken: access, RefreshToken: refresh}, nil
}

func (svc service) invitationKey(ctx context.Context, key Key) (Token, error) {
	var err error
	key.Type = InvitationKey
	key.ExpiresAt = time.Now().Add(svc.invitationDuration)

	key.Subject, err = svc.checkUserDomain(ctx, key)
	if err != nil {
		return Token{}, err
	}

	access, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	return Token{AccessToken: access}, nil
}

func (svc service) refreshKey(ctx context.Context, token string, key Key) (Token, error) {
	k, err := svc.tokenizer.Parse(token)
	if err != nil {
		return Token{}, errors.Wrap(errRetrieve, err)
	}
	if k.Type != RefreshKey {
		return Token{}, errIssueUser
	}
	key.ID = k.ID
	if key.Domain == "" {
		key.Domain = k.Domain
	}
	key.User = k.User
	key.Type = AccessKey

	key.Subject, err = svc.checkUserDomain(ctx, key)
	if err != nil {
		return Token{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	key.ExpiresAt = time.Now().Add(svc.loginDuration)
	access, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	key.ExpiresAt = time.Now().Add(svc.refreshDuration)
	key.Type = RefreshKey
	refresh, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueTmp, err)
	}

	return Token{AccessToken: access, RefreshToken: refresh}, nil
}

func (svc service) checkUserDomain(ctx context.Context, key Key) (subject string, err error) {
	if key.Domain != "" {
		// Check user is platform admin.
		if err = svc.Authorize(ctx, PolicyReq{
			Subject:     key.User,
			SubjectType: UserType,
			Permission:  AdminPermission,
			Object:      MagistralaObject,
			ObjectType:  PlatformType,
		}); err == nil {
			return key.User, nil
		}
		// Check user is domain member.
		domainUserSubject := EncodeDomainUserID(key.Domain, key.User)
		if err = svc.Authorize(ctx, PolicyReq{
			Subject:     domainUserSubject,
			SubjectType: UserType,
			Permission:  MembershipPermission,
			Object:      key.Domain,
			ObjectType:  DomainType,
		}); err != nil {
			return "", err
		}
		return domainUserSubject, nil
	}
	return "", nil
}

func (svc service) userKey(ctx context.Context, token string, key Key) (Token, error) {
	id, sub, err := svc.authenticate(token)
	if err != nil {
		return Token{}, errors.Wrap(errIssueUser, err)
	}

	key.Issuer = id
	if key.Subject == "" {
		key.Subject = sub
	}

	keyID, err := svc.idProvider.ID()
	if err != nil {
		return Token{}, errors.Wrap(errIssueUser, err)
	}
	key.ID = keyID

	if _, err := svc.keys.Save(ctx, key); err != nil {
		return Token{}, errors.Wrap(errIssueUser, err)
	}

	tkn, err := svc.tokenizer.Issue(key)
	if err != nil {
		return Token{}, errors.Wrap(errIssueUser, err)
	}

	return Token{AccessToken: tkn}, nil
}

func (svc service) authenticate(token string) (string, string, error) {
	key, err := svc.tokenizer.Parse(token)
	if err != nil {
		return "", "", errors.Wrap(svcerr.ErrAuthentication, err)
	}
	// Only login key token is valid for login.
	if key.Type != AccessKey || key.Issuer == "" {
		return "", "", svcerr.ErrAuthentication
	}

	return key.Issuer, key.Subject, nil
}

// Switch the relative permission for the relation.
func SwitchToPermission(relation string) string {
	switch relation {
	case AdministratorRelation:
		return AdminPermission
	case EditorRelation:
		return EditPermission
	case ViewerRelation:
		return ViewPermission
	case MemberRelation:
		return MembershipPermission
	default:
		return relation
	}
}

// 使用domianId获取token
func httpGetToken(identity string, secret string, domainID string) (*TokenResponseBody, error) {
	// 用已创建的用户获取新token
	postData := []byte(`{"identity":"` + identity + `","secret":"` + secret + `","domain_id":"` + domainID + `"}`)
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

	return &tokenResponseBody, nil
}

// 创建默认channel
func createDefaultChannel(token string, domain Domain) (Channel, error) {
	// 创建domain时默认创建一个channel
	fmt.Println("domain: ", domain.Name)
	// 要发送的数据
	var channel Channel
	type ChannelPostData struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	// 创建一个Channel结构体的实例
	postChannel := ChannelPostData{
		Name: "default_channel",
		ID:   "",
	}
	jsonBytes, err := json.Marshal(postChannel)
	if err != nil {
		fmt.Println("err createDefaultChannel 111: ", err)
		return Channel{}, err
	}

	postData := jsonBytes
	url := "http://things:9000/channels"
	// 创建请求
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postData))
	if err != nil {
		fmt.Println("err createDefaultChannel 222: ", err)
		return Channel{}, err
	}
	// 设置Header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("err createDefaultChannel 333: ", err)
		return Channel{}, err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("err createDefaultChannel 444: ", err)
		return Channel{}, err
	}
	// 解析JSON字符串到User结构体
	_ = json.Unmarshal(body, &channel)
	return channel, nil
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

// 把这个新domain默认创建的channelId写入userInfo
func updateUserInfo(token string, userInfo UserInfoResponseBody, channelID string, domainID string) error {
	// 要发送的数据
	type UserPostData struct {
		Name     string                 `json:"name"`
		Metadata map[string]interface{} `json:"metadata"`
	}
	var metadata map[string]interface{}
	if userInfo.Metadata == nil || len(userInfo.Metadata) == 0 {
		metadata = map[string]interface{}{}
	} else {
		metadata = userInfo.Metadata
	}
	metadata[domainID] = channelID
	metadata["comID"] = channelID
	postUser := UserPostData{
		Metadata: metadata,
		Name:     userInfo.Name,
	}
	postData, err := json.Marshal(postUser)
	fmt.Println("updateUserInfo data: ", string(postData))
	if err != nil {
		fmt.Println("err updateUserInfo 111: ", err)
		return err
	}
	url := "http://users:9002/users/" + userInfo.ID
	// 创建请求
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(postData))
	if err != nil {
		fmt.Println("err updateUserInfo 222: ", err)
		return err
	}
	// 设置Header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("err updateUserInfo 333: ", err)
		return err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("err updateUserInfo 444: ", err)
		return err
	}
	fmt.Println("Response Status updateUserInfo:", resp.Status)
	fmt.Println("Response Body updateUserInfo:", string(body))
	return nil
}

// 创建默认thing: platform
func createDefaultThing(token, comID string) (mgclients.Client, error) {
	// 要发送的数据
	var thing mgclients.Client
	type ThingPostData struct {
		Name        string                `json:"name"`
		Credentials mgclients.Credentials `json:"credentials"`
	}
	postThing := ThingPostData{
		Name: "Platform" + comID,
		Credentials: mgclients.Credentials{
			Identity: "platform" + comID,
			Secret:   "platform" + comID,
		},
	}
	jsonBytes, err := json.Marshal(postThing)
	if err != nil {
		fmt.Println("err createDefaultThing 111: ", err)
		return mgclients.Client{}, err
	}

	postData := jsonBytes
	url := "http://things:9000/things"
	// 创建请求
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postData))
	if err != nil {
		fmt.Println("err createDefaultThing 222: ", err)
		return mgclients.Client{}, err
	}
	// 设置Header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// 执行请求
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("err createDefaultThing 333: ", err)
		return mgclients.Client{}, err
	}
	defer resp.Body.Close()
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("err createDefaultThing 444: ", err)
		return mgclients.Client{}, err
	}
	// 解析JSON字符串到User结构体
	_ = json.Unmarshal(body, &thing)
	return thing, nil
}

// 创建默认minio bucket文件夹
func createDefaultMinioFolder(comID string) {
	// 创建domain之后，使用domainID创建一个minio的文件夹
	// 初始化 MinIO 客户端
	var minioErr error
	endpoint := os.Getenv("MINIO_ENDPOINT")
	if endpoint == "" {
		endpoint = "minio:9100"
	}
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	if accessKey == "" {
		accessKey = "admin"
	}
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	if secretKey == "" {
		secretKey = "12345678"
	}
	bucketName := os.Getenv("MINIO_BUCKET_NAME")
	if bucketName == "" {
		bucketName = "nxt-tenant"
	}

	minioClient, minioErr = minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})

	if minioErr != nil {
		log.Fatalln(minioErr)
	}

	// 要创建的“文件夹”路径
	folderName := comID + "/"

	// 检查存储桶是否存在
	exists, err := minioClient.BucketExists(context.Background(), bucketName)
	if err != nil {
		log.Fatalln(err)
	}

	if !exists {
		// 创建存储桶
		err = minioClient.MakeBucket(context.Background(), bucketName, minio.MakeBucketOptions{})
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("Successfully created bucket:", bucketName)
	} else {
		fmt.Println("Bucket already exists:", bucketName)
	}

	// 创建一个空的对象，以模拟“文件夹”
	objectName := folderName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, nil, 0, minio.PutObjectOptions{})
	if err != nil {
		log.Fatalln(err)
	}
}

func (svc service) CreateDomain(ctx context.Context, token string, d Domain) (do Domain, err error) {
	key, err := svc.Identify(ctx, token)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	d.CreatedBy = key.User

	domainID, err := svc.idProvider.ID()
	if err != nil {
		return Domain{}, err
	}
	d.ID = domainID

	if d.Status != DisabledStatus && d.Status != EnabledStatus {
		return Domain{}, svcerr.ErrInvalidStatus
	}

	d.CreatedAt = time.Now()

	if err := svc.createDomainPolicy(ctx, key.User, domainID, AdministratorRelation); err != nil {
		return Domain{}, errors.Wrap(errCreateDomainPolicy, err)
	}
	defer func() {
		if err != nil {
			if errRollBack := svc.createDomainPolicyRollback(ctx, key.User, domainID, AdministratorRelation); errRollBack != nil {
				err = errors.Wrap(err, errors.Wrap(errRollbackPolicy, errRollBack))
			}
		}
	}()
	if d.Metadata == nil || len(d.Metadata) == 0 {
		d.Metadata = map[string]interface{}{}
	}
	dom, err := svc.domains.Save(ctx, d)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrCreateEntity, err)
	}

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
		// 获取并打印值
		CurrentUserIdentity, err := rdb.Get(rdctx, "CurrentUserIdentity").Result()
		if err != nil {
			fmt.Printf("Failed to get value from Redis: %v\n", err)
		}
		CurrentUserSecret, err := rdb.Get(rdctx, "CurrentUserSecret").Result()
		if err != nil {
			fmt.Printf("Failed to get value from Redis: %v\n", err)
		}
		//通过新建的用户获取token
		tokenResponseBody, err := httpGetToken(CurrentUserIdentity, CurrentUserSecret, dom.ID)
		if err != nil {
			fmt.Printf("Failed to call the first API: %v\n", err)
		}
		newToken := tokenResponseBody.AccessToken

		//创建默认channel,之后把默认channel的id写入domain的metadata.comID
		newChannel, err := createDefaultChannel(newToken, dom)
		if err != nil {
			fmt.Printf("Failed to call the second API: %v\n", err)
		}
		if newChannel.ID != "" {
			if dom.Metadata == nil {
				dom.Metadata = make(mgclients.Metadata)
			}
			dom.Metadata["comID"] = newChannel.ID
			domainReqData := DomainReq{
				Name:     &dom.Name,
				Tags:     &dom.Tags,
				Alias:    &dom.Alias,
				Status:   &dom.Status,
				Metadata: &dom.Metadata,
			}
			_, err = svc.UpdateDomain(ctx, newToken, dom.ID, domainReqData)
			if err != nil {
				fmt.Printf("Failed to UpdateDomain: %v\n", err)
			}

			//创建默认thing: platform
			_, err = createDefaultThing(newToken, newChannel.ID)
			if err != nil {
				fmt.Printf("Failed to call the third API: %v\n", err)
			}

			// 创建默认minio bucket文件夹
			// createDefaultMinioFolder(newChannel.ID)

			userInfo, err := httpGetUserInfo(newToken)
			if err != nil {
				fmt.Printf("Failed to httpGetUserInfo: %v\n", err)
			} else {
				_ = updateUserInfo(newToken, userInfo, newChannel.ID, dom.ID)
			}
		}
	}

	return dom, nil
}

func (svc service) RetrieveDomain(ctx context.Context, token, id string) (Domain, error) {
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     token,
		SubjectType: UserType,
		SubjectKind: TokenKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  ViewPermission,
	}); err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	dom, err := svc.domains.RetrieveByID(ctx, id)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return dom, nil
}

func (svc service) RetrieveDomainPermissions(ctx context.Context, token, id string) (Permissions, error) {
	res, err := svc.Identify(ctx, token)
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     res.Subject,
		SubjectType: UserType,
		SubjectKind: UsersKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  MembershipPermission,
	}); err != nil {
		return []string{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	lp, err := svc.ListPermissions(ctx, PolicyReq{
		SubjectType: UserType,
		Subject:     res.Subject,
		Object:      id,
		ObjectType:  DomainType,
	}, []string{AdminPermission, EditPermission, ViewPermission, MembershipPermission})
	if err != nil {
		return []string{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return lp, nil
}

func (svc service) UpdateDomain(ctx context.Context, token, id string, d DomainReq) (Domain, error) {
	key, err := svc.Identify(ctx, token)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     key.Subject,
		SubjectType: UserType,
		SubjectKind: UsersKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  EditPermission,
	}); err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	dom, err := svc.domains.Update(ctx, id, key.User, d)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return dom, nil
}

func (svc service) ChangeDomainStatus(ctx context.Context, token, id string, d DomainReq) (Domain, error) {
	key, err := svc.Identify(ctx, token)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     key.Subject,
		SubjectType: UserType,
		SubjectKind: UsersKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  AdminPermission,
	}); err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}

	dom, err := svc.domains.Update(ctx, id, key.User, d)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return dom, nil
}

func (svc service) ListDomains(ctx context.Context, token string, p Page) (DomainsPage, error) {
	key, err := svc.Identify(ctx, token)
	if err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	p.SubjectID = key.User
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     key.User,
		SubjectType: UserType,
		Permission:  AdminPermission,
		ObjectType:  PlatformType,
		Object:      MagistralaObject,
	}); err == nil {
		p.SubjectID = ""
	}
	dp, err := svc.domains.ListDomains(ctx, p)
	if err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	if p.SubjectID == "" {
		for i := range dp.Domains {
			dp.Domains[i].Permission = AdministratorRelation
		}
	}
	return dp, nil
}

func (svc service) AssignUsers(ctx context.Context, token, id string, userIds []string, relation string) error {
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     token,
		SubjectType: UserType,
		SubjectKind: TokenKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  SharePermission,
	}); err != nil {
		return err
	}

	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     token,
		SubjectType: UserType,
		SubjectKind: TokenKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  SwitchToPermission(relation),
	}); err != nil {
		return err
	}

	for _, userID := range userIds {
		if err := svc.Authorize(ctx, PolicyReq{
			Subject:     userID,
			SubjectType: UserType,
			Permission:  MembershipPermission,
			Object:      MagistralaObject,
			ObjectType:  PlatformType,
		}); err != nil {
			return errors.Wrap(svcerr.ErrMalformedEntity, fmt.Errorf("invalid user id : %s ", userID))
		}
	}

	return svc.addDomainPolicies(ctx, id, relation, userIds...)
}

func (svc service) UnassignUsers(ctx context.Context, token, id string, userIds []string, relation string) error {
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     token,
		SubjectType: UserType,
		SubjectKind: TokenKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  SharePermission,
	}); err != nil {
		return err
	}

	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     token,
		SubjectType: UserType,
		SubjectKind: TokenKind,
		Object:      id,
		ObjectType:  DomainType,
		Permission:  SwitchToPermission(relation),
	}); err != nil {
		return err
	}

	if err := svc.removeDomainPolicies(ctx, id, relation, userIds...); err != nil {
		return errors.Wrap(errRemovePolicies, err)
	}
	return nil
}

// IMPROVEMENT NOTE: Take decision: Only Patform admin or both Patform and domain admins can see others users domain.
func (svc service) ListUserDomains(ctx context.Context, token, userID string, p Page) (DomainsPage, error) {
	res, err := svc.Identify(ctx, token)
	if err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := svc.Authorize(ctx, PolicyReq{
		Subject:     res.User,
		SubjectType: UserType,
		Permission:  AdminPermission,
		Object:      MagistralaObject,
		ObjectType:  PlatformType,
	}); err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if userID != "" && res.User != userID {
		p.SubjectID = userID
	} else {
		p.SubjectID = res.User
	}
	dp, err := svc.domains.ListDomains(ctx, p)
	if err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return dp, nil
}

func (svc service) addDomainPolicies(ctx context.Context, domainID, relation string, userIDs ...string) (err error) {
	var prs []PolicyReq
	var pcs []Policy

	for _, userID := range userIDs {
		prs = append(prs, PolicyReq{
			Subject:     EncodeDomainUserID(domainID, userID),
			SubjectType: UserType,
			SubjectKind: UsersKind,
			Relation:    relation,
			Object:      domainID,
			ObjectType:  DomainType,
		})
		pcs = append(pcs, Policy{
			SubjectType: UserType,
			SubjectID:   userID,
			Relation:    relation,
			ObjectType:  DomainType,
			ObjectID:    domainID,
		})
	}
	if err := svc.agent.AddPolicies(ctx, prs); err != nil {
		return errors.Wrap(errAddPolicies, err)
	}
	defer func() {
		if err != nil {
			if errDel := svc.agent.DeletePolicies(ctx, prs); errDel != nil {
				err = errors.Wrap(err, errors.Wrap(errRollbackPolicy, errDel))
			}
		}
	}()

	if err = svc.domains.SavePolicies(ctx, pcs...); err != nil {
		return errors.Wrap(errAddPolicies, err)
	}
	return nil
}

func (svc service) createDomainPolicy(ctx context.Context, userID, domainID, relation string) (err error) {
	prs := []PolicyReq{
		{
			Subject:     EncodeDomainUserID(domainID, userID),
			SubjectType: UserType,
			SubjectKind: UsersKind,
			Relation:    relation,
			Object:      domainID,
			ObjectType:  DomainType,
		},
		{
			Subject:     MagistralaObject,
			SubjectType: PlatformType,
			Relation:    PlatformRelation,
			Object:      domainID,
			ObjectType:  DomainType,
		},
	}
	if err := svc.agent.AddPolicies(ctx, prs); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if errDel := svc.agent.DeletePolicies(ctx, prs); errDel != nil {
				err = errors.Wrap(err, errors.Wrap(errRollbackPolicy, errDel))
			}
		}
	}()
	err = svc.domains.SavePolicies(ctx, Policy{
		SubjectType: UserType,
		SubjectID:   userID,
		Relation:    relation,
		ObjectType:  DomainType,
		ObjectID:    domainID,
	})
	if err != nil {
		return errors.Wrap(errCreateDomainPolicy, err)
	}
	return err
}

func (svc service) createDomainPolicyRollback(ctx context.Context, userID, domainID, relation string) error {
	var err error
	prs := []PolicyReq{
		{
			Subject:     EncodeDomainUserID(domainID, userID),
			SubjectType: UserType,
			SubjectKind: UsersKind,
			Relation:    relation,
			Object:      domainID,
			ObjectType:  DomainType,
		},
		{
			Subject:     MagistralaObject,
			SubjectType: PlatformType,
			Relation:    PlatformRelation,
			Object:      domainID,
			ObjectType:  DomainType,
		},
	}
	if errPolicy := svc.agent.DeletePolicies(ctx, prs); errPolicy != nil {
		err = errors.Wrap(errRemovePolicyEngine, errPolicy)
	}
	errPolicyCopy := svc.domains.DeletePolicies(ctx, Policy{
		SubjectType: UserType,
		SubjectID:   userID,
		Relation:    relation,
		ObjectType:  DomainType,
		ObjectID:    domainID,
	})
	if errPolicyCopy != nil {
		err = errors.Wrap(err, errors.Wrap(errRemoveLocalPolicy, errPolicyCopy))
	}
	return err
}

func (svc service) removeDomainPolicies(ctx context.Context, domainID, relation string, userIDs ...string) (err error) {
	var prs []PolicyReq
	var pcs []Policy

	for _, userID := range userIDs {
		prs = append(prs, PolicyReq{
			Subject:     EncodeDomainUserID(domainID, userID),
			SubjectType: UserType,
			SubjectKind: UsersKind,
			Relation:    relation,
			Object:      domainID,
			ObjectType:  DomainType,
		})
		pcs = append(pcs, Policy{
			SubjectType: UserType,
			SubjectID:   userID,
			Relation:    relation,
			ObjectType:  DomainType,
			ObjectID:    domainID,
		})
	}
	if err := svc.agent.DeletePolicies(ctx, prs); err != nil {
		return errors.Wrap(errRemovePolicies, err)
	}
	err = svc.domains.DeletePolicies(ctx, pcs...)
	if err != nil {
		return errors.Wrap(errRemovePolicies, err)
	}
	return err
}

func EncodeDomainUserID(domainID, userID string) string {
	if domainID == "" || userID == "" {
		return ""
	}
	return domainID + "_" + userID
}

func DecodeDomainUserID(domainUserID string) (string, string) {
	if domainUserID == "" {
		return domainUserID, domainUserID
	}
	duid := strings.Split(domainUserID, "_")

	switch {
	case len(duid) == 2:
		return duid[0], duid[1]
	case len(duid) == 1:
		return duid[0], ""
	case len(duid) == 0 || len(duid) > 2:
		fallthrough
	default:
		return "", ""
	}
}

func (svc service) DeleteEntityPolicies(ctx context.Context, entityType, id string) (err error) {
	switch entityType {
	case ThingType:
		req := PolicyReq{
			Object:     id,
			ObjectType: ThingType,
		}

		return svc.DeletePolicyFilter(ctx, req)
	case UserType:
		domainsPage, err := svc.domains.ListDomains(ctx, Page{SubjectID: id, Limit: defLimit})
		if err != nil {
			return err
		}

		if domainsPage.Total > defLimit {
			for i := defLimit; i < int(domainsPage.Total); i += defLimit {
				page := Page{SubjectID: id, Offset: uint64(i), Limit: defLimit}
				dp, err := svc.domains.ListDomains(ctx, page)
				if err != nil {
					return err
				}
				domainsPage.Domains = append(domainsPage.Domains, dp.Domains...)
			}
		}

		for _, domain := range domainsPage.Domains {
			policy := PolicyReq{
				Subject:     EncodeDomainUserID(domain.ID, id),
				SubjectType: UserType,
			}
			if err := svc.agent.DeletePolicy(ctx, policy); err != nil {
				return err
			}
		}

		req := PolicyReq{
			Subject:     id,
			SubjectType: UserType,
		}
		if err := svc.agent.DeletePolicy(ctx, req); err != nil {
			return err
		}

		if err := svc.domains.DeleteUserPolicies(ctx, id); err != nil {
			return err
		}

		return nil
	case GroupType:
		req := PolicyReq{
			SubjectType: GroupType,
			Subject:     id,
		}
		if err := svc.DeletePolicyFilter(ctx, req); err != nil {
			return err
		}

		req = PolicyReq{
			Object:     id,
			ObjectType: GroupType,
		}
		return svc.DeletePolicyFilter(ctx, req)
	default:
		return errInvalidEntityType
	}
}
