.PHONY: dev clean

# Generate a test instance with default values
dev:
	rm -rf /tmp/djast-dev
	copier copy . /tmp/djast-dev --defaults --trust
	@echo ""
	@echo "Test instance created at /tmp/djast-dev"
	@echo "  cd /tmp/djast-dev/MyProject && docker compose up --build"

clean:
	rm -rf /tmp/djast-dev
