.PHONY: help backend cli frontend dev build install up down logs clean

BACKEND_PORT ?= 8080
ARGS ?=

help:
	@echo "make backend    run the Go backend"
	@echo "make cli        run the CLI (ARGS='inspect ./agent-dir')"
	@echo "make frontend   run the Next.js dev server"
	@echo "make install    install frontend dependencies"
	@echo "make build      build backend, cli and frontend"
	@echo "make up         docker compose up --build (backend + frontend)"
	@echo "make down       docker compose down"
	@echo "make logs       tail docker compose logs"
	@echo "make clean      remove build output"

backend:
	# build + exec instead of `go run`, which exits 1 when interrupted
	cd backend && go build -o ../bin/capm-backend ./cmd && PORT=$(BACKEND_PORT) ../bin/capm-backend

cli:
	go run ./cli $(ARGS)

frontend:
	cd frontend && npm run dev

install:
	cd frontend && npm ci

build:
	cd backend && go build -o ../bin/capm-backend ./cmd
	cd cli && go build -o ../bin/capm .
	cd frontend && npm run build

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	rm -rf bin frontend/.next
