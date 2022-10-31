#!/bin/bash

# Copyright (c) 2022, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

# This script generates the docs for the verrazzano APIs.

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

if ! command -v go &>/dev/null; then
    echo "go must be installed"
    exit 1
fi

tmpdir="$(mktemp -d)"

cleanup() {
	# we can't simply remove tmpdir because the modcache is written as read-only
	# and we'll get permissions errors, so we use go clean instead
	export GO111MODULE="auto"
	echo "+++ Cleaning up temporary GOPATH"
	go clean -modcache

	rm -rf "${tmpdir}"
}
trap cleanup EXIT

# Create fake GOPATH
echo "+++ Creating temporary GOPATH"
export GOPATH="${tmpdir}/go"
export GO111MODULE="on"
GOROOT="$(go env GOROOT)"
export GOROOT
GOBIN="${tmpdir}/bin"
export GOBIN

go install github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0

mkdir -p "${GOPATH}/src/github.com/verrazzano"
gitdir="${GOPATH}/src/github.com/verrazzano/verrazzano"
echo "+++ Cloning verrazzano repository..."
git clone "https://github.com/verrazzano/verrazzano.git" "$gitdir"
cd "$gitdir"

checkout() {
	branch="$1"
	pushd "$gitdir"
	echo "+++ Checking out branch $branch"
	git fetch origin "$branch"
	git reset --hard "origin/$branch"
}

genapidoc() {
  API=$1
  OUTFILE=${REPO_ROOT}/content/en/docs/reference/API/$2.md
	echo "+++ Generating API reference doc for ${API}"
	"${GOBIN}/gen-crd-api-reference-docs" \
		-config "${REPO_ROOT}/scripts/genapidocs/config.json" \
		-template-dir "${REPO_ROOT}/scripts/genapidocs/template" \
		-api-dir "github.com/verrazzano/verrazzano/${API}" \
		-out-file "${OUTFILE}"
	# Prepending header info to the generated file
	printf '%s\n%s\n%s\n%s\n%s\n' "---" "title: ${API}" "weight: 2" "---" "$(cat ${OUTFILE})" >${OUTFILE}
}

checkout "$1"
genapidoc "platform-operator/apis/clusters/v1alpha1" "vpo-clusters-v1alpha1"
genapidoc "platform-operator/apis/verrazzano/v1alpha1" "vpo-verrazzano-v1alpha1"
#popd
