.PHONY: help install test lint format clean demo run-tests coverage

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run test suite"
	@echo "  make lint       - Run linters"
	@echo "  make format     - Format code with black"
	@echo "  make demo       - Run demo script"
	@echo "  make coverage   - Generate coverage report"
	@echo "  make clean      - Clean generated files"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy

test:
	pytest tests/ -v

run-tests:
	pytest tests/ -v --cov=src --cov-report=term-missing

coverage:
	pytest tests/ --cov=src --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

lint:
	flake8 src/ tests/ --max-line-length=100 --extend-ignore=E203,W503
	mypy src/ --ignore-missing-imports || true

format:
	black src/ tests/ demo.py

demo:
	python demo.py

scan-test-repo:
	python -m src.main --repo-path test_repo/ --verbose

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache htmlcov/ .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf dist/ build/ *.egg-info
	rm -rf reports/ models/
