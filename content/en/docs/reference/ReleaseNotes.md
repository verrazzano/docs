---
title: Release Notes
linkTitle: Release Notes
weight: 4
draft: false
---

### v.0.7.0
- Features
    - Ability to upgrade an existing Verrazzano installation.
    - Added the Verrazzano Console.
    - Enhanced the structure of the Verrazzano custom resource to allow more configurability.
    - Streamlined the secret usage for OCI DNS installations.

- Fixes
    - Fixed bug where the Verrazzano CR Certificate.`CA` fields were being ignored.
    - Removed secret used for `hello-world`; `hello-world-application` image is now public in ghcr so `ImagePullSecrets` is no longer needed.

### v0.6.0:
- Features
    - A new in-cluster installer is provided, obsoleting the previous installs scripts
    - Added Install profiles, there are 2 in this release, prod and dev
    - All logs are now structured, written in JSON format with timestamps in RFC3339 format
- Fixes
    - Arbitrary and WLS domain secrets are now being copied from the model, fix for https://github.com/verrazzano/verrazzano/issues/339
    - Versions of Elasticsearch and Kibana were updated to resolve security issues

