---
title: Release Notes
linkTitle: Release Notes
weight: 4
draft: false
---

### v0.8.0
- Features
    - Support for two installation profiles, development (dev) and production (prod).  The production profile, which is the default, provides a 3-node Elasticsearch and persistent storage for the Verrazzano Monitoring Instance (VMI). The development profile provides a single node Elasticsearch and no persistent storage for the VMI.   
    - The default behavior has been changed to use the system VMI for all monitoring (applications and Verrazzano components).  It is still possible to customize one of the profiles to enable the original non-shared VMI mode.
    - Initial support for the Open Application Model (OAM), stay tuned for more updates.
- Fixes
    - Updated Axios NPM package to v0.21.1 to resolve CVE-2020-28168 in examples code.

### v.0.7.0
- Features
    - Ability to upgrade an existing Verrazzano installation.
    - Added the Verrazzano Console.
    - Enhanced the structure of the Verrazzano custom resource to allow more configurability.
    - Streamlined the secret usage for OCI DNS installations.

- Fixes
    - Fixed bug where the Verrazzano CR `Certificate.CA` fields were being ignored.
    - Removed secret used for `hello-world`; `hello-world-application` image is now public in ghcr so `ImagePullSecrets` is no longer needed.
    - Fixed [issue #339](https://github.com/verrazzano/verrazzano/issues/339) (PRs [#208](https://github.com/verrazzano/verrazzano-operator/pull/208) & [#210](https://github.com/verrazzano/verrazzano-operator/pull/210).)

### v0.6.0
- Features
    - In-cluster installer which replaces client-side install scripts.
    - Added installation profiles; in this release, there are two: production and development.
    - Verrazzano system components now emit JSON structured logs.
- Fixes
    - Updated Elasticsearch and Kibana versions (elasticsearch:7.6.1-20201130145440-5c76ab1) and (kibana:7.6.1-20201130145840-7717e73).
