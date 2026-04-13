.PHONY: setup up down logs demo attack-replay attack-travel test lint

# ─── Setup ────────────────────────────────────────────────────────────────────

setup: ## Generate RSA keypair and copy .env
	@echo "Generating RSA-2048 keypair for JWT RS256..."
	@bash scripts/generate-keys.sh
	@if [ ! -f .env ]; then cp .env.example .env && echo "Created .env from .env.example — update secrets before use"; fi
	@echo "Setup complete. Run 'make up' to start."

# ─── Docker ───────────────────────────────────────────────────────────────────

up: ## Start all services
	docker compose up --build -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@docker compose ps

down: ## Stop all services
	docker compose down

logs: ## Tail all service logs
	docker compose logs -f membership-service entitlement-service audit-service

# ─── Demo ─────────────────────────────────────────────────────────────────────

demo: ## Run the full happy-path demo
	@bash scripts/demo.sh

attack-replay: ## Simulate a QR code replay attack (expect DENIED on 2nd call)
	@bash scripts/attack_simulation.sh replay

attack-travel: ## Simulate an impossible travel attack (expect security alert)
	@bash scripts/attack_simulation.sh travel

# ─── Dev ──────────────────────────────────────────────────────────────────────

test: ## Run all service tests
	cd services/membership-service && npm test
	cd services/audit-service && npm test
	cd services/entitlement-service && python -m pytest

lint: ## Lint all services
	cd services/membership-service && npm run lint
	cd services/audit-service && npm run lint
	cd services/entitlement-service && python -m ruff check .

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
