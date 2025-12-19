# The Force Security ASM - Makefile
.PHONY: help build up down restart logs shell db-shell init-db clean dev

# Default target
help:
	@echo "The Force Security - Attack Surface Management"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build Docker images"
	@echo "  up          Start all services"
	@echo "  down        Stop all services"
	@echo "  restart     Restart all services"
	@echo "  logs        View container logs"
	@echo "  shell       Open shell in backend container"
	@echo "  db-shell    Open PostgreSQL shell"
	@echo "  init-db     Initialize database with seed data"
	@echo "  clean       Remove containers, volumes, and images"
	@echo "  dev         Start services with development tools (Adminer)"
	@echo ""

# Build Docker images
build:
	docker-compose build

# Start all services
up:
	docker-compose up -d
	@echo ""
	@echo "Services started!"
	@echo "  - API:     http://localhost:8000"
	@echo "  - Docs:    http://localhost:8000/api/docs"
	@echo ""

# Start with development tools
dev:
	docker-compose --profile dev up -d
	@echo ""
	@echo "Services started (development mode)!"
	@echo "  - API:      http://localhost:8000"
	@echo "  - Docs:     http://localhost:8000/api/docs"
	@echo "  - Adminer:  http://localhost:8080"
	@echo ""

# Stop all services
down:
	docker-compose --profile dev down

# Restart services
restart: down up

# View logs
logs:
	docker-compose logs -f

# Open shell in backend container
shell:
	docker-compose exec backend /bin/bash

# Open PostgreSQL shell
db-shell:
	docker-compose exec db psql -U asm_user -d asm_db

# Initialize database with seed data
init-db:
	docker-compose exec backend python -m app.scripts.init_db

# Clean everything
clean:
	docker-compose --profile dev down -v --rmi local
	@echo "Cleaned up containers, volumes, and images."

# Run tests
test:
	docker-compose exec backend pytest -v

# Show service status
status:
	docker-compose ps















