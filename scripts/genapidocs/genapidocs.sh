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

if [ $# -eq 0 ]
  then
    echo "Branch name must be specified"
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

echo "+++ Installing gen-crd-api-reference-docs"
go install github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0

mkdir -p "${GOPATH}/src/github.com/verrazzano"
gitdir="${GOPATH}/src/github.com/verrazzano/verrazzano"
echo "+++ Cloning verrazzano repository"
git clone "https://github.com/verrazzano/verrazzano.git" "$gitdir"
cd "$gitdir"

checkoutvz() {
	branch="$1"
	echo "+++ Checking out verrazzano branch $branch"
	git fetch origin "$branch"
	git reset --hard "origin/$branch"
}

genapidoc() {
  API=$1
  OUTFILE=${REPO_ROOT}/content/en/docs/reference/$2.md
  TITLE=$3
  WEIGHT=$4
  ALIAS=$5
	echo "+++ Generating API reference doc for ${API}"
	"${GOBIN}/gen-crd-api-reference-docs" \
		-config "${REPO_ROOT}/scripts/genapidocs/config.json" \
		-template-dir "${REPO_ROOT}/scripts/genapidocs/template" \
		-api-dir "github.com/verrazzano/verrazzano/${API}" \
		-out-file "${OUTFILE}"
	# Prepending header info to the generated file
	printf '%s\n%s\n%s\n%s\n%s\n%s\n' "---" "title: ${TITLE}" "weight: ${WEIGHT}" "aliases:" "  - ${ALIAS}" "---" "$(cat ${OUTFILE})" >${OUTFILE}
}

checkoutvz "$1"
genapidoc "application-operator/apis/clusters/v1alpha1" "vao-clusters-v1alpha1" "Multicluster and Verrazzano Project" "1" "/docs/reference/apis/vao-clusters-v1alpha1"
genapidoc "application-operator/apis/oam/v1alpha1" "vao-oam-v1alpha1" "Traits and Workloads" "2" "/docs/reference/api/vao-oam-v1alpha1"
genapidoc "cluster-operator/apis/clusters/v1alpha1" "vco-clusters-v1alpha1" "Verrazzano Managed Cluster" "3" "/docs/reference/api/vco-clusters-v1alpha1"
genapidoc "platform-operator/apis/verrazzano/v1beta1" "vpo-verrazzano-v1beta1" "Verrazzano v1beta1 APIs" "4" "/docs/reference/api/vpo-verrazzano-v1beta1"
genapidoc "platform-operator/apis/verrazzano/v1alpha1" "vpo-verrazzano-v1alpha1" "Verrazzano v1alpha1 APIs" "5" "/docs/reference/api/vpo-verrazzano-v1alpha1"

cd ${REPO_ROOT}

# Sometimes gen-crd-api-reference-docs generates the reference apis/meta instead of meta.
# Fix them up if that is the case.
sed -i -e 's,apis/meta,meta,g' content/en/docs/reference/*.md

# Check to see if any files are checked out of the docs repo.  Files will be checked out when there is a change in
# the generated API reference docs.
if [[ `git status --porcelain --untracked-files=no` ]]; then
  echo "+++ Changes found in the generated API reference docs"
else
  echo "+++ No changes found in the generated API reference docs"
fi
