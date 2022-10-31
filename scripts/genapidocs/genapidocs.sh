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
#apidocstmpdir="$(mktemp -d)"

cleanup() {
	# we can't simply remove tmpdir because the modcache is written as read-only
	# and we'll get permissions errors, so we use go clean instead
	export GO111MODULE="auto"
	echo "+++ Cleaning up temporary GOPATH"
	go clean -modcache

#	rm -rf "${apidocstmpdir}"
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

# genversion takes two arguments (branch in verrazzano repo and a directory in
# this repo under content) and generates API reference docs from cert-manager
# branch for the path in this repo.
genversion() {
	checkout "$1"
	gendocs
}

checkout() {
	branch="$1"
	pushd "$gitdir"
#	rm -rf vendor/
	echo "+++ Checking out branch $branch"
	git fetch origin "$branch"
	git reset --hard "origin/$branch"
#	echo "+++ Running 'go mod vendor' (this may take a while)"
#	go mod vendor
}

gendocs() {
#	outputdir="$1"
#	mkdir -p ${apidocstmpdir}/${outputdir}/
	echo "+++ Generating reference docs..."
	"${GOBIN}/gen-crd-api-reference-docs" \
		-config "${REPO_ROOT}/scripts/genapidocs/config.json" \
		-template-dir "${REPO_ROOT}/scripts/genapidocs/template" \
		-api-dir "github.com/verrazzano/verrazzano/platform-operator/apis/clusters/v1alpha1" \
		-out-file "api-docs.md"

#	rm -rf vendor/
	popd
}


# The branches named here exist in the `cert-manager/cert-manager` repo.

# Note that we cannot generate docs for any version before 1.8 using this script!
# In 1.8 we changed the import path, and gen-crd-api-reference-docs doesn't seem module-aware
# This script is _only_ for generating docs for versions of cert-manager with the
# github.com/cert-manager/cert-manager import path!

#LATEST_VERSION="v1.10-docs"

genversion "$1"

# Rather than generate the same docs again for /docs, copy from the latest version

#cp -r "${REPO_ROOT}/content/${LATEST_VERSION}/reference" "${REPO_ROOT}/content/docs/"

# Unless we keep the next release branch up-to-date (which we never do), it's pointless to generate reference docs for next-docs.
# Instead just use the same as we have for docs.

#cp -r "${REPO_ROOT}/content/${LATEST_VERSION}/reference" "${REPO_ROOT}/content/next-docs/"

echo "Generated reference documentation for cert-manager versions with a new github.com/cert-manager/cert-manager import path"

