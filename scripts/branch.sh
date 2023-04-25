#!/bin/bash

#
# Copyright (c) 2023, Oracle and/or its affiliates.
#

set -e

RELEASE_BRANCH=$1

if [[ ${RELEASE_BRANCH} == release-* ]]; then
  VERSION=v${RELEASE_BRANCH:8:3}
  echo "Publish ${VERSION}"
  echo "VERSION=${VERSION}" >> "$GITHUB_ENV"
elif [[ ${RELEASE_BRANCH} == master ]]; then
  VERSION=devel
  echo "Publish master as ${VERSION}"
  echo "VERSION=${VERSION}" >> "$GITHUB_ENV"
elif [[ ${RELEASE_BRANCH} == archive ]]; then
  VERSION=archive
  echo "Publish archive to the archive sub-directory"
  echo "VERSION=${VERSION}" >> "$GITHUB_ENV"
else
  echo "${RELEASE_BRANCH} is not a release branch.  Can not publish."
  exit 1
fi