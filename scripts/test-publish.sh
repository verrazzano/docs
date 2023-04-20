#!/bin/bash

#
# Copyright (c) 2021, Oracle and/or its affiliates.
#

IS_LATEST=$(<.latest)

set -e

PUBLISH_BRANCH=gh-pages

RELEASE_BRANCH=$1

echo ${RELEASE_BRANCH}
pwd
ls production