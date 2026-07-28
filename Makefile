.PHONY: help install_dev package build build_linux clean test unittest lint format docs pdocs rst_auto test_cli python37 catalog_update catalog_check check

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

RANGE_DIR      ?= .
RANGE_TEST_DIR := ${TEST_DIR}/${RANGE_DIR}
RANGE_SRC_DIR  := ${SRC_DIR}/${RANGE_DIR}

COV_TYPES ?= xml term-missing
MIN_COVERAGE ?= 90

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
	@echo "                      RANGE_DIR=<path> MIN_COVERAGE=<n>"
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
		--cov="${RANGE_SRC_DIR}" \
		$(if ${MIN_COVERAGE},--cov-fail-under=${MIN_COVERAGE},)

python37:
	$(PYTHON37) -m pytest ${TEST_DIR} -sv -m unittest

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
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend supported
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend available
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend versions mihomo --limit 2
	$(PYTHON) -m jerryproxy --home "${BUILD_DIR}/test-home" backend artifact mihomo

catalog_update:
	$(PYTHON) -m tools.backend_catalog

catalog_check:
	$(PYTHON) -m tools.backend_catalog --validate-only

check: lint catalog_check unittest pdocs package test_cli
