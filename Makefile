.PHONY: help install_dev package build clean test unittest lint format docs pdocs test_cli python37 check

PYTHON ?= $(shell which python)
PYTHON37 ?= python3.7

PROJ_DIR      := .
DOC_DIR       := ${PROJ_DIR}/docs
BUILD_DIR     := ${PROJ_DIR}/build
DIST_DIR      := ${PROJ_DIR}/dist
TEST_DIR      := ${PROJ_DIR}/test
SRC_DIR       := ${PROJ_DIR}/jerryproxy

RANGE_DIR      ?= .
RANGE_TEST_DIR := ${TEST_DIR}/${RANGE_DIR}
RANGE_SRC_DIR  := ${SRC_DIR}/${RANGE_DIR}

COV_TYPES ?= xml term-missing

help:
	@echo "JerryProxy Build System"
	@echo "======================="
	@echo ""
	@echo "Environment:"
	@echo "  make install_dev  - Install package and development/test/doc dependencies"
	@echo ""
	@echo "Building and packaging:"
	@echo "  make package      - Build source and wheel distributions"
	@echo "  make build        - Build one standalone CLI with PyInstaller"
	@echo "  make test_cli     - Smoke-test source and standalone CLI entry points"
	@echo "  make clean        - Remove generated artifacts"
	@echo ""
	@echo "Testing and quality:"
	@echo "  make test         - Alias for make unittest"
	@echo "  make unittest     - Run pytest with coverage"
	@echo "                      RANGE_DIR=<path> MIN_COVERAGE=<n>"
	@echo "  make python37     - Run unit tests through python3.7"
	@echo "  make lint         - Run ruff checks"
	@echo "  make format       - Format Python with ruff"
	@echo "  make check        - Run lint, unit tests, docs, and package checks"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs         - Build Sphinx HTML documentation"
	@echo "  make pdocs        - Build docs with production warnings enabled"

install_dev:
	$(PYTHON) -m pip install -e .
	$(PYTHON) -m pip install -r requirements-test.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -r requirements-doc.txt
	$(PYTHON) -m pip install -r requirements-build.txt

package:
	$(PYTHON) -m build --sdist --wheel --outdir ${DIST_DIR}
	$(PYTHON) -m twine check ${DIST_DIR}/*.whl ${DIST_DIR}/*.tar.gz

build:
	$(PYTHON) -m PyInstaller --clean --onefile --console --name jerryproxy jerryproxy_cli.py

clean:
	rm -rf ${DIST_DIR} ${BUILD_DIR} *.egg-info .pytest_cache .ruff_cache
	rm -f .coverage coverage.xml junit.xml jerryproxy.spec
	$(MAKE) -C ${DOC_DIR} clean

test: unittest

unittest:
	pytest "${RANGE_TEST_DIR}" \
		-sv -m unittest \
		--junitxml=junit.xml -o junit_family=legacy \
		$(shell for type in ${COV_TYPES}; do echo "--cov-report=$$type"; done) \
		--cov="${RANGE_SRC_DIR}" \
		$(if ${MIN_COVERAGE},--cov-fail-under=${MIN_COVERAGE},)

python37:
	$(PYTHON37) -m pytest ${TEST_DIR} -sv -m unittest

lint:
	ruff check ${SRC_DIR} ${TEST_DIR} jerryproxy_cli.py setup.py

format:
	ruff format ${SRC_DIR} ${TEST_DIR} jerryproxy_cli.py setup.py

docs:
	$(MAKE) -C "${DOC_DIR}" build

pdocs:
	SPHINXOPTS="-W --keep-going" $(MAKE) -C "${DOC_DIR}" build

test_cli:
	$(PYTHON) -m jerryproxy --version
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" home
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend supported
	$(if $(wildcard ${DIST_DIR}/jerryproxy*),${DIST_DIR}/jerryproxy --version,true)

check: lint unittest pdocs package test_cli
