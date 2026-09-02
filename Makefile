MIGRATIONS := internal/db/migrations
DB_URL     ?= $(DATABASE_URL)
GOOSE := goose -dir $(MIGRATIONS) postgres "$(DB_URL)"

run:
	go run cmd/server/main.go
goose-up:
	$(GOOSE) up
goose-down:
	$(GOOSE) down
goose-create:
	goose -dir $(MIGRATIONS) create $(NAME) sql