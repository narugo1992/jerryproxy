.PHONY: help install_dev package build build_linux clean test unittest e2e_check lint format docs pdocs rst_auto test_cli python37 catalog_update catalog_check archive_corpus archive_corpus_check relay_health_sync relay_health_check relay_health_wiki relay_health_gate check

PYTHON ?= $(shell which python)
PYTHON37 ?= python3.7
DOCKER ?= docker
DOCKER_RUN_ARGS ?=

LINUX_BUILD_IMAGE ?= python@sha256:f678e6659fcd0a3fd4e3426f46b0b534253b0971da34dca6ce5b0c6e49b7cd64

PROJ_DIR      := .
DOC_DIR       := ${PROJ_DIR}/docs
BUILD_DIR     := ${PROJ_DIR}/build
DIST_DIR      := ${PROJ_DIR}/dist
TEST_DIR      := ${PROJ_DIR}/test
SRC_DIR       := ${PROJ_DIR}/jerryproxy
TOOLS_DIR     := ${PROJ_DIR}/tools

RELAY_HEALTH_GIST_ID ?= 78fb0ee6135fcdf4f0e5c7ec38f2fd59
RELAY_HEALTH_TARGETS_URL ?= https://gist.githubusercontent.com/narugo1992/${RELAY_HEALTH_GIST_ID}/raw/relay_health_targets.json
RELAY_HEALTH_TARGETS ?= ${PROJ_DIR}/relay_health_targets.json
RELAY_HEALTH_RESULTS ?= ${PROJ_DIR}/relay_health_latest.json
RELAY_HEALTH_WIKI ?= ${PROJ_DIR}/Relay-Health.md
RELAY_HEALTH_TIMEOUT ?= 10
RELAY_HEALTH_ATTEMPTS ?= 3
RELAY_HEALTH_VANTAGE ?= local

RANGE_DIR      ?= .
RANGE_TEST_DIR := ${TEST_DIR}/${RANGE_DIR}
E2E_TEST_DIR   := ${TEST_DIR}/e2e
RANGE_SRC_DIR  := ${SRC_DIR}/${RANGE_DIR}

COV_TYPES ?= xml term-missing

PYTHON_CODE_DIR   := ${SRC_DIR}
RST_DOC_DIR       := ${DOC_DIR}/source/api_doc
PYTHON_CODE_FILES := $(shell find ${RANGE_SRC_DIR} -name "*.py" ! -name "__*.py" 2>/dev/null)
RST_DOC_FILES     := $(patsubst ${PYTHON_CODE_DIR}/%.py,${RST_DOC_DIR}/%.rst,${PYTHON_CODE_FILES})
PYTHON_INIT_FILES := $(shell find ${RANGE_SRC_DIR} -name "__init__.py" 2>/dev/null)
RST_INIT_FILES    := $(foreach file,${PYTHON_INIT_FILES},$(patsubst %/__init__.py,%/index.rst,$(patsubst ${PYTHON_CODE_DIR}/%,${RST_DOC_DIR}/%,$(patsubst ${PYTHON_CODE_DIR}/__init__.py,${RST_DOC_DIR}/index.rst,${file}))))

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
	@echo "  make build_linux  - Build Linux CLI in the pinned Python 3.7 Docker image"
	@echo "  make test_cli     - Smoke-test source CLI entry points"
	@echo "  make clean        - Remove generated artifacts"
	@echo ""
	@echo "Testing and quality:"
	@echo "  make test         - Alias for make unittest"
	@echo "  make unittest     - Run pytest with coverage"
	@echo "  make e2e_check     - Verify the harness assets offline"
	@echo "                      RANGE_DIR=<path>"
	@echo "  make python37     - Run unit tests through python3.7"
	@echo "  make lint         - Run ruff checks"
	@echo "  make format       - Format Python with ruff"
	@echo "  make check        - Run lint, unit tests, docs, and package checks"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs         - Build Sphinx HTML documentation"
	@echo "  make pdocs        - Build docs with production warnings enabled"
	@echo "  make rst_auto     - Generate English RST API docs from Python source"
	@echo "                      RANGE_DIR=<path>"
	@echo "  make catalog_update - Refresh the packaged backend catalog from GitHub"
	@echo "  make catalog_check  - Validate the packaged catalog without network access"
	@echo "  make archive_corpus - Download and measure pinned official backend archives"
	@echo "  make archive_corpus_check - Validate the checked archive measurements offline"
	@echo "  make relay_health_sync - Download relay targets from the health Gist"
	@echo "  make relay_health_check - Probe the local relay target JSON"
	@echo "  make relay_health_wiki - Render local relay JSON as Wiki Markdown"
	@echo "  make relay_health_gate - Reject malformed or integrity-mismatch results"

install_dev:
	$(PYTHON) -m pip install -e .
	$(PYTHON) -m pip install -r requirements-test.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -r requirements-doc.txt
	$(PYTHON) -m pip install -r requirements-build.txt

package:
	rm -rf ${DIST_DIR} ${BUILD_DIR} *.egg-info
	mkdir -p ${DIST_DIR}
	$(PYTHON) -m build --sdist --wheel --outdir ${DIST_DIR}
	$(PYTHON) -m twine check ${DIST_DIR}/*.whl ${DIST_DIR}/*.tar.gz

build:
	$(PYTHON) -m PyInstaller --clean --onefile --console --collect-data jerryproxy --name jerryproxy jerryproxy_cli.py

build_linux:
	mkdir -p ${DIST_DIR}
	$(DOCKER) run --rm $(DOCKER_RUN_ARGS) \
		--user "$$(id -u):$$(id -g)" \
		--env HOME=/tmp \
		--volume "$(CURDIR):/workspace:ro" \
		--volume "$(abspath ${DIST_DIR}):/dist" \
		${LINUX_BUILD_IMAGE} /bin/sh -eu -c '\
			python -m venv /tmp/jerryproxy-build; \
			/tmp/jerryproxy-build/bin/python -m pip install "pip<24.1"; \
			/tmp/jerryproxy-build/bin/python -m pip install /workspace -r /workspace/requirements-build.txt; \
			cd /tmp; \
			/tmp/jerryproxy-build/bin/python -m PyInstaller --clean --onefile --console \
				--collect-data jerryproxy \
				--name jerryproxy --distpath /dist --workpath /tmp/pyinstaller-build \
				--specpath /tmp /workspace/jerryproxy_cli.py; \
			/dist/jerryproxy --version'

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
		--cov="${RANGE_SRC_DIR}"

python37:
	$(PYTHON37) -m pytest ${TEST_DIR} -sv -m unittest

# Offline invariants of the harness assets: no Docker, no network.
e2e_check:
	cd ${TOOLS_DIR}/e2e && $(PYTHON) check.py

lint:
	ruff check ${SRC_DIR} ${TEST_DIR} ${TOOLS_DIR} jerryproxy_cli.py setup.py auto_rst.py auto_rst_top_index.py

format:
	ruff format ${SRC_DIR} ${TEST_DIR} ${TOOLS_DIR} jerryproxy_cli.py setup.py auto_rst.py auto_rst_top_index.py

docs: rst_auto
	$(MAKE) -C "${DOC_DIR}" build

pdocs: rst_auto
	SPHINXOPTS="-W --keep-going" $(MAKE) -C "${DOC_DIR}" build

rst_auto: ${RST_DOC_FILES} ${RST_INIT_FILES} auto_rst_top_index.py
	$(PYTHON) auto_rst_top_index.py -i ${PYTHON_CODE_DIR} -o ${DOC_DIR}/source

${RST_DOC_DIR}/%.rst: ${PYTHON_CODE_DIR}/%.py auto_rst.py Makefile
	@mkdir -p $(dir $@)
	$(PYTHON) auto_rst.py -i $< -o $@ --source-root ${PROJ_DIR}

${RST_DOC_DIR}/%/index.rst: ${PYTHON_CODE_DIR}/%/__init__.py auto_rst.py Makefile
	@mkdir -p $(dir $@)
	$(PYTHON) auto_rst.py -i $< -o $@ --source-root ${PROJ_DIR}

${RST_DOC_DIR}/index.rst: ${PYTHON_CODE_DIR}/__init__.py auto_rst.py Makefile
	@mkdir -p $(dir $@)
	$(PYTHON) auto_rst.py -i $< -o $@ --source-root ${PROJ_DIR}

test_cli:
	$(PYTHON) -m jerryproxy --version
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" home
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" self-check --color
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend list known
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend list known mihomo --limit 2
	version="$$( $(PYTHON) -m jerryproxy backend list known mihomo --limit 1 --json | $(PYTHON) -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])' )"; \
		$(PYTHON) -m jerryproxy backend list known mihomo "$$version"
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend current

catalog_update:
	$(PYTHON) -m tools.backend_catalog

catalog_check:
	$(PYTHON) -m tools.backend_catalog --validate-only

archive_corpus:
	$(PYTHON) -m tools.archive_corpus --download

archive_corpus_check:
	$(PYTHON) -m tools.archive_corpus --validate-only

relay_health_sync:
	curl --fail --location --silent --show-error \
		--max-time 30 \
		--max-filesize 1048576 \
		--output "${RELAY_HEALTH_TARGETS}.tmp" \
		"${RELAY_HEALTH_TARGETS_URL}?refresh=$$(date +%s)"
	mv "${RELAY_HEALTH_TARGETS}.tmp" "${RELAY_HEALTH_TARGETS}"

relay_health_check:
	$(PYTHON) -m tools.relay_health \
		--targets "${RELAY_HEALTH_TARGETS}" \
		--output "${RELAY_HEALTH_RESULTS}" \
		--timeout "${RELAY_HEALTH_TIMEOUT}" \
		--attempts "${RELAY_HEALTH_ATTEMPTS}" \
		--vantage "${RELAY_HEALTH_VANTAGE}"

relay_health_wiki:
	$(PYTHON) -m tools.render_relay_health \
		--targets "${RELAY_HEALTH_TARGETS}" \
		--results "${RELAY_HEALTH_RESULTS}" \
		--output "${RELAY_HEALTH_WIKI}"

relay_health_gate:
	$(PYTHON) -m tools.relay_health --gate-results "${RELAY_HEALTH_RESULTS}"

check: lint catalog_check archive_corpus_check unittest pdocs package test_cli
