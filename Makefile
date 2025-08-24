SHELL := /usr/bin/env bash
IMAGE ?= ovh-dedicated-cli
DH_NS ?= <dockerhub_user>
GH_NS ?= <github_user>
VERSION ?= v0.1.0
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build push run web cli
build:
	docker buildx build --platform $(PLATFORMS) -t docker.io/$(DH_NS)/$(IMAGE):$(VERSION) -t docker.io/$(DH_NS)/$(IMAGE):latest -t ghcr.io/$(GH_NS)/$(IMAGE):$(VERSION) -t ghcr.io/$(GH_NS)/$(IMAGE):latest --push .

run:
	docker run --rm -p 8000:8000 --env-file ./.env docker.io/$(DH_NS)/$(IMAGE):latest

web: run

cli:
	docker run --rm --env-file ./.env docker.io/$(DH_NS)/$(IMAGE):latest python ovh_dedicated.py $(ARGS)
