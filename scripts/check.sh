#!/bin/bash

set -e

DOCS_DIR="content"

ls $DOCS_DIR

if grep -nrP -e "\(https://verrazzano.io/(?!v[0-9]\.[0-9]/|archive/)" .; then
  echo "Replace references to https://verrazzano.io wih relative references"
  exit 1
fi

