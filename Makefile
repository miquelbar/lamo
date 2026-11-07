# Local Development & Testing Makefile
# Infrastructure and application operations are handled via ./lamo (see: ./lamo --help)

.PHONY: help test clean

help:
	@echo "Local Development & Testing"
	@echo ""
	@echo "Usage:"
	@echo "  make test      Run automated unit test suite"
	@echo "  make clean     Clean Python bytecode, pycache and temporary files"
	@echo ""
	@echo "Infrastructure and application operations are handled by the CLI orchestrator:"
	@echo "  ./lamo --help"
	@echo "  ./lamo node --help"
	@echo "  ./lamo app --help"

test: ## Run automated unit test suite
	@python3 -m unittest discover -s tests -v

clean: ## Clean bytecode, cache and temporary files
	@find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf /tmp/ssh-mux-* 2>/dev/null || true
	@echo "==> Workspace cleaned."
