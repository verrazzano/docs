#!/bin/bash

#
# Copyright (c) 2021, Oracle and/or its affiliates.
#

IS_LATEST=$(<.latest)

set -e

PUBLISH_BRANCH=gh-pages

RELEASE_BRANCH=$1

function install_gh-pages() {
  sudo npm -g install gh-pages@3.0.0
  git config --global credential.helper "!f() { echo username=\\$GIT_AUTH_USR; echo password=\\$GIT_AUTH_PSW; }; f"
  git config --global user.name "${GIT_AUTH_USR}"
  git config --global user.email "${EMAIL}"
  sudo chmod -R o+wx /usr/lib/node_modules
}

function ensureRoot() {
    /usr/bin/gh-pages -b ${PUBLISH_BRANCH} -d hack -a
}

if [[ ${RELEASE_BRANCH} == release-* ]]; then
  install_gh-pages
  VERSION=v${RELEASE_BRANCH:8}
  echo "publish ${VERSION}"
  /usr/bin/gh-pages -d production -b ${PUBLISH_BRANCH} -e "${VERSION}"
  if [[ "true" == "${IS_LATEST}" ]]; then
    echo "publish ${VERSION} as the latest"
    /usr/bin/gh-pages -d production -b ${PUBLISH_BRANCH} -e latest
  fi
  ensureRoot
elif [[ ${RELEASE_BRANCH} == master ]]; then
  install_gh-pages
  echo "publish master as devel"
  /usr/bin/gh-pages -d production -b ${PUBLISH_BRANCH} -e devel
  ensureRoot
elif [[ ${RELEASE_BRANCH} == archive ]]; then
  install_gh-pages
  echo "publish archive to the archive sub-directory"
  /usr/bin/gh-pages -d production -b ${PUBLISH_BRANCH} -e archive
else
  echo "${RELEASE_BRANCH} is not a release branch.  Can not publish."
  exit 1
fi