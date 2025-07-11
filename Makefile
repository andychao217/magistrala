# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

MG_DOCKER_IMAGE_ALIYUN_PREFIX ?= registry.cn-hangzhou.aliyuncs.com
MG_DOCKER_IMAGE_USERNAME_PREFIX ?= andychao217
MG_DOCKER_IMAGE_NAME_PREFIX ?= magistrala
ALIYUN_DOCKER_PASSWORD ?= Andy986372
ALIYUN_DOCKER_USERNAME ?= andychao217
BUILD_DIR = build
SERVICES = auth users things http coap ws mqtt invitations \
	influxdb-writer influxdb-reader mongodb-writer mongodb-reader smtp-notifier smpp-notifier \
	cassandra-writer cassandra-reader postgres-writer postgres-reader timescale-writer timescale-reader \
	cli bootstrap opcua twins lora provision certs vault
TEST_API_SERVICES = auth bootstrap certs http invitations notifiers provision readers things twins users
TEST_API = $(addprefix test_api_,$(TEST_API_SERVICES))
DOCKERS = $(addprefix docker_,$(SERVICES))
DOCKERS_DEV = $(addprefix docker_dev_,$(SERVICES))
CGO_ENABLED ?= 0
GOOS ?= linux
GOARCH ?= arm64
VERSION ?= $(shell git describe --abbrev=0 --tags)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
USER_REPO ?= $(shell git remote get-url origin | sed -e 's/.*\/\([^/]*\)\/\([^/]*\).*/\1_\2/' )
empty:=
space:= $(empty) $(empty)
# Docker compose project name should follow this guidelines: https://docs.docker.com/compose/reference/#use--p-to-specify-a-project-name
DOCKER_PROJECT ?= $(shell echo $(subst $(space),,$(USER_REPO)) | tr -c -s '[:alnum:][=-=]' '_' | tr '[:upper:]' '[:lower:]')
DOCKER_COMPOSE_COMMANDS_SUPPORTED := up down config
DEFAULT_DOCKER_COMPOSE_COMMAND  := up
GRPC_MTLS_CERT_FILES_EXISTS = 0
MOCKERY_VERSION=v2.42.1
ifneq ($(MG_MESSAGE_BROKER_TYPE),)
    MG_MESSAGE_BROKER_TYPE := $(MG_MESSAGE_BROKER_TYPE)
else
    MG_MESSAGE_BROKER_TYPE=nats
endif

ifneq ($(MG_ES_TYPE),)
    MG_ES_TYPE := $(MG_ES_TYPE)
else
    MG_ES_TYPE=nats
endif

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -tags $(MG_MESSAGE_BROKER_TYPE) --tags $(MG_ES_TYPE) -ldflags "-s -w \
	-X 'github.com/andychao217/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/andychao217/magistrala.Version=$(VERSION)' \
	-X 'github.com/andychao217/magistrala.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/$(1) cmd/$(1)/main.go
endef

define make_docker
	$(eval svc=$(subst docker_,,$(1)))

	docker buildx build --platform=linux/amd64,linux/arm64 \
		--no-cache \
		--build-arg SVC=$(svc) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$(svc) \
		--tag=$(MG_DOCKER_IMAGE_ALIYUN_PREFIX)/$(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$(svc) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	$(eval svc=$(subst docker_dev_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--tag=$(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$(svc) \
		-f docker/Dockerfile.dev ./build
endef

ADDON_SERVICES = bootstrap cassandra-reader cassandra-writer certs \
	influxdb-reader influxdb-writer lora-adapter mongodb-reader mongodb-writer \
	opcua-adapter postgres-reader postgres-writer provision smpp-notifier smtp-notifier \
	timescale-reader timescale-writer twins vault

EXTERNAL_SERVICES = vault prometheus

ifneq ($(filter run%,$(firstword $(MAKECMDGOALS))),)
  temp_args := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  DOCKER_COMPOSE_COMMAND := $(if $(filter $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)), $(filter $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)), $(DEFAULT_DOCKER_COMPOSE_COMMAND))
  $(eval $(DOCKER_COMPOSE_COMMAND):;@)
endif

ifneq ($(filter run_addons%,$(firstword $(MAKECMDGOALS))),)
  temp_args := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  RUN_ADDON_ARGS :=  $(if $(filter-out $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)), $(filter-out $(DOCKER_COMPOSE_COMMANDS_SUPPORTED),$(temp_args)),$(ADDON_SERVICES) $(EXTERNAL_SERVICES))
  $(eval $(RUN_ADDON_ARGS):;@)
endif

ifneq ("$(wildcard docker/ssl/certs/*-grpc-*)","")
GRPC_MTLS_CERT_FILES_EXISTS = 1
else
GRPC_MTLS_CERT_FILES_EXISTS = 0
endif

FILTERED_SERVICES = $(filter-out $(RUN_ADDON_ARGS), $(SERVICES))

all: $(SERVICES)

.PHONY: all $(SERVICES) dockers dockers_dev latest release run run_addons grpc_mtls_certs check_mtls check_certs test_api

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker compose -f docker/docker-compose.yml -p $(DOCKER_PROJECT) down --rmi all -v --remove-orphans

ifdef pv
	# Remove unused volumes
	docker volume ls -f name=$(MG_DOCKER_IMAGE_NAME_PREFIX) -f dangling=true -q | xargs -r docker volume rm
endif

install:
	for file in $(BUILD_DIR)/*; do \
		cp $$file $(GOBIN)/magistrala-`basename $$file`; \
	done

mocks:
	@which mockery > /dev/null || go install github.com/vektra/mockery/v2@$(MOCKERY_VERSION)
	@unset MOCKERY_VERSION && go generate ./...


DIRS = consumers readers postgres internal opcua
test: mocks
	mkdir -p coverage
	@for dir in $(DIRS); do \
        go test -v --race -count 1 -tags test -coverprofile=coverage/$$dir.out $$(go list ./... | grep $$dir | grep -v 'cmd'); \
    done
	go test -v --race -count 1 -tags test -coverprofile=coverage/coverage.out $$(go list ./... | grep -v 'consumers\|readers\|postgres\|internal\|opcua\|cmd')

define test_api_service
	$(eval svc=$(subst test_api_,,$(1)))
	@which st > /dev/null || (echo "schemathesis not found, please install it from https://github.com/schemathesis/schemathesis#getting-started" && exit 1)

	@if [ -z "$(USER_TOKEN)" ]; then \
		echo "USER_TOKEN is not set"; \
		echo "Please set it to a valid token"; \
		exit 1; \
	fi

	st run api/openapi/$(svc).yml \
	--checks all \
	--base-url $(2) \
	--header "Authorization: Bearer $(USER_TOKEN)" \
	--contrib-openapi-formats-uuid \
	--hypothesis-suppress-health-check=filter_too_much \
	--stateful=links
endef

test_api_users: TEST_API_URL := http://localhost:9002
test_api_things: TEST_API_URL := http://localhost:9000
test_api_invitations: TEST_API_URL := http://localhost:9020
test_api_auth: TEST_API_URL := http://localhost:8189
test_api_bootstrap: TEST_API_URL := http://localhost:9013
test_api_certs: TEST_API_URL := http://localhost:9019

$(TEST_API):
	$(call test_api_service,$(@),$(TEST_API_URL))

proto:
	protoc -I. --go_out=. --go_opt=paths=source_relative pkg/messaging/*.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./*.proto

$(FILTERED_SERVICES):
	$(call compile_service,$(@))

$(DOCKERS):
	$(call make_docker,$(@),$(GOARCH))

$(DOCKERS_DEV):
	$(call make_docker_dev,$(@))

dockers: $(DOCKERS)
dockers_dev: $(DOCKERS_DEV)

define docker_push
	for svc in $(SERVICES); do \
		docker push $(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$(SVC):$(1); \
		docker push ${MG_DOCKER_IMAGE_ALIYUN_PREFIX}/$(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$(SVC):$(1) \
	done
endef

changelog:
	git log $(shell git describe --tags --abbrev=0)..HEAD --pretty=format:"- %s"

latest: dockers
	$(call docker_push,latest)

release:
	$(eval version = $(shell git describe --abbrev=0 --tags))
	git checkout $(version)
	$(MAKE) dockers
	for svc in $(SERVICES); do \
		docker tag $(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$$svc $(MG_DOCKER_IMAGE_USERNAME_PREFIX)/$(MG_DOCKER_IMAGE_NAME_PREFIX)-$$svc:$(version); \
	done
	$(call docker_push,$(version))

rundev:
	cd scripts && ./run.sh

grpc_mtls_certs:
	$(MAKE) -C docker/ssl auth_grpc_certs things_grpc_certs

check_tls:
# ifeq ($(GRPC_TLS),true)
# 	@unset GRPC_MTLS
# 	@echo "gRPC TLS is enabled"
# 	GRPC_MTLS=
# else
# 	@unset GRPC_TLS
# 	GRPC_TLS=
# endif

check_mtls:
# ifeq ($(GRPC_MTLS),true)
# 	@unset GRPC_TLS
# 	@echo "gRPC MTLS is enabled"
# 	GRPC_TLS=
# else
# 	@unset GRPC_MTLS
# 	@GRPC_MTLS=
# endif

check_certs: check_mtls check_tls
ifeq ($(GRPC_MTLS_CERT_FILES_EXISTS),0)
ifeq ($(filter true,$(GRPC_MTLS) $(GRPC_TLS)),true)
ifeq ($(filter $(DEFAULT_DOCKER_COMPOSE_COMMAND),$(DOCKER_COMPOSE_COMMAND)),$(DEFAULT_DOCKER_COMPOSE_COMMAND))
	$(MAKE) -C docker/ssl auth_grpc_certs things_grpc_certs
endif
endif
endif

run: check_certs login
	docker compose -f docker/docker-compose.yml --env-file docker/.env -p $(DOCKER_PROJECT) $(DOCKER_COMPOSE_COMMAND) $(args)

run_addons: check_certs
	$(foreach SVC,$(RUN_ADDON_ARGS),$(if $(filter $(SVC),$(ADDON_SERVICES) $(EXTERNAL_SERVICES)),,$(error Invalid Service $(SVC))))
	@for SVC in $(RUN_ADDON_ARGS); do \
		MG_ADDONS_CERTS_PATH_PREFIX="../."  docker compose -f docker/addons/$$SVC/docker-compose.yml -p $(DOCKER_PROJECT) --env-file ./docker/.env $(DOCKER_COMPOSE_COMMAND) $(args) & \
	done

login:
	@if [ -n "$(ALIYUN_DOCKER_PASSWORD)" ]; then \
		echo "Logging in to registry.cn-hangzhou.aliyuncs.com..."; \
		echo "$(ALIYUN_DOCKER_PASSWORD)" | docker login -u "$(ALIYUN_DOCKER_USERNAME)" --password-stdin registry.cn-hangzhou.aliyuncs.com; \
	else \
		echo "Error: ALIYUN_DOCKER_PASSWORD environment variable not set"; \
		exit 1; \
	fi