---
title: Release Notes
linkTitle: Release Notes
weight: 13
draft: false
---

### v0.17.0
Features:
- Allow Verrazzano Monitoring Instance (VMI) replicas and memory sizes to be changed during installation for both `dev` and `prod` profiles.
- When installing Verrazzano on OKE, the OKE-specific Fluentd `extraVolumeMounts` configuration is no longer required.
- Updated to the v3.2.5 WebLogic Kubernetes Operator.

Fixes:
- During uninstall, delete application resources only from namespaces which are managed by Verrazzano.
- During upgrade, honor the APP_OPERATOR_IMAGE override.
- Fixed Keycloak installation failure when Prometheus is disabled.
- Allow empty values for Helm overrides in `config.json`.

### v0.16.0
Features:
- Provided options to configure log volume/mount of the log collector, Fluentd, and pre-configured profiles.
- Automatically enabled metrics and log capture for WebLogic domains deployed in Verrazzano.
- Added security-related data/project YAML files to the Verrazzano console, under project details.
- Updated to the v3.2.4 WebLogic Kubernetes Operator.

Fixes:
- Added a fix for default metrics traits not always being injected into the `appconfig`.
- Updated the timestamp in WebLogic application logs so that the time filter can be used in Kibana.
- Corrected the incorrect `podSelector` in the node exporter network policy.  
- Fixed the DNS resolution issue due to the missing cluster section of the `coredns configmap`.
- Stability improvements for the platform, tests, and examples.
- Renamed the Elasticsearch fields in a multicluster registration secret to be consistent.

### v0.15.1
Features:
- Allow customization of Elasticsearch node sizes and topology during installation.
- If `runtimeEncryptionSecret`, specified in the WebLogic domain spec, does not already exist, then create it.
- Support overrides of persistent storage configuration for Elasticsearch, Kibana, Prometheus, Grafana, and Keycloak.

Known Issues:
- After upgrade to 0.15.1, for Verrazzano Custom Resource installed on OCI Container Engine for Kubernetes (OKE), the Fluentd DaemonSet in the `verrazzano-system` namespace cannot access logs.
  Run following command to patch the Fluentd DaemonSet and correct the issue:
  ```
  kubectl patch -n verrazzano-system ds fluentd --patch '{"spec":{"template":{"spec":{"containers":[{"name": "fluentd","volumeMounts":[{"mountPath":"/u01/data/","name":"extravol0","readOnly":true}]}],"volumes":[{"hostPath":{"path":"/u01/data/","type":""},"name":"extravol0"}]}}}}'
  ```

### v0.15.0
Features:
- Support for private container registries.
- Secured communication between Verrazzano resources using Istio.
- Updated to the following versions:
    - cert-manager to 1.2.0.
    - Coherence Operator to 3.1.5.
    - WebLogic Kubernetes Operator to 3.2.3.
    - Node Exporter to 1.0.0.
    - NGINX Ingress Controller to 0.46.
    - Fluentd to 1.12.3.
- Added network policies for Istio.

Fixes:
- Stability improvements for the platform, tests, and examples.
- Several fixes for scraping Prometheus metrics.
- Several fixes for logging and Elasticsearch.
- Replaced `keycloak.json` with dynamic realm creation.
- Removed the LoggingScope CRD from the Verrazzano API.
- Fixed issues related to multicluster resources being orphaned.

### v0.14.0
Features:
- Multicluster support for Verrazzano. Now you can:
    - Register participating clusters as VerrazzanoManagedClusters.
    - Deploy MutiClusterComponents and MultiClusterApplicationConfigurations.
    - Organize multicluster namespaces as VerrazzanoProjects.
    - Access MultiCluster Components and ApplicationConfigurations in the Verrazzano Console UI.
- Changed default wildcard DNS from xip.io to nip.io.
- Support for OKE clusters with private endpoints.
- Support for network policies. Now you can:
    - Add ingress-NGINX network policies.
    - Add Rancher network policies.
    - Add NetworkPolicy support to Verrazzano projects.
    - Add network policies for Keycloak.
    - Add platform operator network policies.
    - Add network policies for Elasticsearch and Kibana.
    - Set network policies for Verrazzano operators, console, and API proxy.
    - Add network policies for WebLogic Kubernetes Operator.
- Changes to allow magic DNS provider to be specified (xip.io, nip.io, sslip.io).
- Support service setup for multiple containers.
- Enabled use of self-signed certs with OCI DNS.
- Support for setting DeploymentStrategy for VerrazzanoHelidonWorkload.

Fixes:

- Several stability improvements for the platform, tests, and examples.
- Added retries around lookup of Rancher admin user.
- Granted specific privileges instead of `ALL` for Keycloak user in MySQL.
- Disabled the installation of the Verrazzano Console UI on managed clusters.

### v0.13.0
Features:
- `IngressTrait` support for explicit destination host and port.
- Experimental cluster diagnostic tooling.
- Grafana dashboards for `VerrazzanoHelidonWorkload`.
- Now you can update application Fluentd sidecar images following a Verrazzano update.
- Documented Verrazzano specific OAM workload resources.
- Documented Verrazzano hardware requirements and installed software versions.

Fixes:
- `VerrazzanoWebLogicWorkload` and `VerrazzanoCoherenceWorkload` resources now handle updates.
- Now `VerrazzanoHelidonWorkload` supports the use of the `ManualScalarTrait`.
- Now you can delete a `Namespace` containing an `ApplicationConfiguration` resource.
- Fixed frequent restarts of Prometheus during application deployment.
- Made `verrazzano-application-operator` logging more useful and use structured logging.
- Fixed Verrazzano uninstall issues.

### v0.12.0
Features:
- Observability stack now uses Keycloak SSO for authentication.
- Istio sidecars now automatically injected when namespaces labeled `istio-injection=enabled`.
- Support for Helidon applications now defined using `VerrazzanoHelidonWorkload` type.

Fixes:
- Fixed issues where logs were not captured from all containers in workloads with multiple containers.
- Fixed issue where some resources were not cleaned up during uninstall.

### v0.11.0

Features:
- OAM applications are optionally deployed into an Istio service mesh.
- Incremental improvements to user-facing roles.

Fixes:
- Fixed issue with logging when an application has multiple workload types.
- Fixed metrics configuration in Spring Boot example application.

### v0.10.0

**Breaking Changes**:
- Model/binding files removed; now application deployment done exclusively by using Open Application Model (OAM).
- Syntax changes for WebLogic and Coherence OAM workloads, now defined using `VerrazzanoCoherenceWorkload`
  and `VerrazzanoWebLogicWorkload` types.

Features:
  - By default, application endpoints now use HTTPs - when using magic DNS, certificates are issued by cluster issuer, when using
    OCI DNS certificates are issued using Let's Encrypt, or the end user can provide certificates.
  - Updated Coherence operator to 3.1.3.
  - Updates for running Verrazzano on Kubernetes 1.19 and 1.20.
  - RBAC roles and role bindings created at install time.
  - Added instance information to status of Verrazzano custom resource; can be used to obtain instance URLs.
  - Upgraded Istio to v1.7.3.

Fixes:
  - Reduced log level of Elasticsearch; excessive logging could have resulted in filling up disks.

### v0.9.0
- Features:
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
- Features:
    - Support for two installation profiles, development (`dev`) and production (`prod`).  The production profile, which is the default, provides a 3-node Elasticsearch and persistent storage for the Verrazzano Monitoring Instance (VMI). The development profile provides a single node Elasticsearch and no persistent storage for the VMI.
    - The default behavior has been changed to use the system VMI for all monitoring (applications and Verrazzano components).  It is still possible to customize one of the profiles to enable the original, non-shared VMI mode.
    - Initial support for the Open Application Model (OAM).
- Fixes:
    - Updated Axios NPM package to v0.21.1 to resolve a security vulnerability in the examples code.

### v.0.7.0
- Features:
    - Ability to upgrade an existing Verrazzano installation.
    - Added the Verrazzano Console.
    - Enhanced the structure of the Verrazzano custom resource to allow more configurability.
    - Streamlined the secret usage for OCI DNS installations.

- Fixes:
    - Fixed bug where the Verrazzano CR `Certificate.CA` fields were being ignored.
    - Removed secret used for `hello-world`; `hello-world-application` image is now public in ghcr so `ImagePullSecrets` is no longer needed.
    - Fixed [issue #339](https://github.com/verrazzano/verrazzano/issues/339) (PRs [#208](https://github.com/verrazzano/verrazzano-operator/pull/208) & [#210](https://github.com/verrazzano/verrazzano-operator/pull/210).)

### v0.6.0
- Features:
    - In-cluster installer which replaces client-side install scripts.
    - Added installation profiles; in this release, there are two: production and development.
    - Verrazzano system components now emit JSON structured logs.
- Fixes:
    - Updated Elasticsearch and Kibana versions (elasticsearch:7.6.1-20201130145440-5c76ab1) and (kibana:7.6.1-20201130145840-7717e73).
