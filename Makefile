.PHONY: build test scan watch redteam

build:
	go build ./...

test:
	go test ./...
	cd redteam && uv run --extra dev ruff check . && uv run --extra dev pytest -q

scan:
	go run ./cmd/vanguard scan

watch:
	go run ./cmd/vanguard watch -interval 1h

redteam:
	cd redteam && uv run --extra dev pytest -q
