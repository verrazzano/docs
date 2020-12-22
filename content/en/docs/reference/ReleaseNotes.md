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

