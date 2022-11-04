# Copyright (C) 2022, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

SCRIPT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/scripts

# Target to generate the API reference docs.
.PHONY: generate-api
generate-api:
	$(SCRIPT_DIR)/genapidocs/genapidocs.sh $(BRANCH)

# Target to launch hugo locally for viewing/testing.  hugo needs to be previously installed.
.PHONY: hugo
hugo:
	hugo server --environment local

# Target to generate the API reference docs and launch hugo for viewing/testing.
.PHONY: generate-api-hugo
generate-api-hugo: generate-api hugo
