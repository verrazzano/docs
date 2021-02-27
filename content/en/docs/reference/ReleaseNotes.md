---
title: Release Notes
linkTitle: Release Notes
weight: 4
draft: false
---

### v0.11.0:

Features
- OAM applications are optionally deployed into an Istio service mesh.
- Incremental improvements to user-facing roles.

Fixes
- Fixed issue with logging when an application has multiple workload types.
- Fixed metrics configuration in Spring Boot example application.

### v0.10.0:

**Breaking Changes**
- Model/binding files removed; now application deployment done exclusively by using Open Application Model (OAM).
- Syntax changes for WebLogic and Coherence OAM workloads, now defined using `VerrazzanoCoherenceWorkload`
  and `VerrazzanoWebLogicWorkload` types.

Features
  - By default, application endpoints now use HTTPs - when using magic DNS, certificates are issued by cluster issuer, when using
    OCI DNS certificates are issued using Let's Encrypt, or the end user can provide certificates.
  - Updated Coherence operator to 3.1.3.
  - Updates for running Verrazzano on Kubernetes 1.19 and 1.20.
  - RBAC roles and role bindings created at install time.
  - Added instance information to status of Verrazzano custom resource; can be used to obtain instance URLs.
  - Upgraded Istio to v1.7.3.

Fixes
  - Reduced log level of Elasticsearch; excessive logging could have resulted in filling up disks.

### v0.9.0:
- Features
    - Added platform support for installing Verrazzano on Kind clusters.
    - Log records are indexed from the OAM `appconfig` and `component` definitions using the following pattern: `namespace-appconfig-component`.
    - All system and curated components are now patchable.
    - More updates to Open Application Model (OAM) support.

To enable OAM, when you install Verrazzano, specify the following in the Kubernetes manifest file for the Verrazzano custom resource:

```shell
spec:
  oam:
    enabled: true
```


### v0.8.0
- Features
    - Support for two installation profiles, development (`dev`) and production (`prod`).  The production profile, which is the default, provides a 3-node Elasticsearch and persistent storage for the Verrazzano Monitoring Instance (VMI). The development profile provides a single node Elasticsearch and no persistent storage for the VMI.   
    - The default behavior has been changed to use the system VMI for all monitoring (applications and Verrazzano components).  It is still possible to customize one of the profiles to enable the original, non-shared VMI mode.
    - Initial support for the Open Application Model (OAM).
- Fixes
    - Updated Axios NPM package to v0.21.1 to resolve a security vulnerability in the examples code.

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
