#!/bin/bash

#
# Copyright (c) 2021, Oracle and/or its affiliates.
#

set -e

BRANCH_NAME=$1

LATEST_VERSION=$2

if [[ ${BRANCH_NAME} == release-* ]]; then
  VERSION=v${BRANCH_NAME:8}
  sudo npm -g install gh-pages@3.0.0
  git config --global credential.helper "!f() { echo username=\\$GIT_AUTH_USR; echo password=\\$GIT_AUTH_PSW; }; f"
  git config --global user.name $GIT_AUTH_USR
  git config --global user.email "${EMAIL}"
  sudo chmod -R o+wx /usr/lib/node_modules
  if [[ "${VERSION}" == "${LATEST_VERSION}" ]]; then
    echo "publish ${VERSION} as the latest"
    /usr/bin/gh-pages -d production -b gh-pages -e latest
  else
    echo "publish ${VERSION}"
    /usr/bin/gh-pages -d production -b gh-pages -e ${VERSION}
  fi
else
  echo "${BRANCH_NAME} is not a release branch.  Can not publish."
  exit 1
fi
