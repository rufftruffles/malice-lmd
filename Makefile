ORG=malice
NAME=lmd
CATEGORY=av
VERSION=$(shell cat VERSION)

.PHONY: build
build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	@docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: clean
clean:
	docker image rm $(ORG)/$(NAME):$(VERSION) || true
	docker image rm $(ORG)/$(NAME):latest || true
