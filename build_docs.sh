#!/usr/bin/env bash
set -e

LIB_NAME=xrootdlib
DOCS_DIR=docs

cd ${DOCS_DIR}
touch source/api/dummy
rm source/api/*
sphinx-apidoc --module-first --separate --output-dir=source/api ../${LIB_NAME} --force && \
python3 $(which sphinx-build) -b html -d build/doctrees . build/html/ && \
open build/html/index.html
