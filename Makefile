.PHONY: build test scan watch inventory fix ui posture redteam demo dogfood

build:
	go build ./...

test:
	go test ./...
	cd redteam && uv run --extra dev ruff check . && uv run --extra dev pytest -q

scan:
	go run ./cmd/vanguard scan

watch:
	go run ./cmd/vanguard watch -interval 1h

inventory:
	go run ./cmd/vanguard inventory

fix:
	go run ./cmd/vanguard fix

ui:
	go run ./cmd/vanguard ui

posture:
	go run ./cmd/vanguard posture

redteam:
	cd redteam && uv run --extra dev pytest -q

demo:
	cd redteam && python3 demo/demo_target.py 3456

# One command that runs both loops against the box you're on: the reactive CVM
# scan + hardware inventory, then the proactive frontier-model red-team against
# the in-repo demo target. The red-team leg needs DEEPSEEK_API_KEY.
dogfood: inventory scan
	@echo
	@echo "=== proactive red-team (frontier model vs demo target) ==="
	@if [ -z "$$DEEPSEEK_API_KEY" ]; then \
		echo "DEEPSEEK_API_KEY not set — skipping the frontier-model red-team run."; \
		echo "Set it, then re-run:  make dogfood"; \
	else \
		cd redteam && (python3 demo/demo_target.py 3456 >/tmp/vanguard-demo.log 2>&1 &) && sleep 1 && \
		uv run --extra dev python demo/run_attack.py http://localhost:3456 10; \
		pkill -f 'demo_target.py 3456' 2>/dev/null || true; \
	fi
