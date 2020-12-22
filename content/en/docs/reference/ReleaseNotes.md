---
title: Release Notes
linkTitle: Release Notes
weight: 4
draft: false
---

### v.0.7.0
- Features
    - Ability to upgrade an exiting Verrazzano installation
    - The Verrazzano Console has been added 
    - The structure of the Verrazzano custom resource has been enhanced to allow more configurability
    - Streamlined the secret usage for OCI DNS installations

- Fixes
    - Fix bug where the verrazzano CR Certificate.CA fields were being ignored
    - Removed secret use for hello-world, hello-world-application image is now public in ghcr so ImagePullSecrets is no longer needed

