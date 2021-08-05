---
title: "Software Versions"
description: "Software versions used by Verrazzano"
weight: 7
draft: false
---
This page describes the software versions installed and supported by Verrazzano.

## Kubernetes
Verrazzano can be installed on the following Kubernetes releases:
- 1.18
- 1.19
- 1.20

See the [Kubernetes Release Documentation](https://kubernetes.io/releases/) for more information.
Also refer to [Verrazzano platform setup]({{< relref "/docs/setup/platforms/_index.md" >}}) for platform specific details.

## WebLogic
The supported versions of WebLogic are dependent on the WebLogic Kubernetes Operator version.
Currently, the following WebLogic versions are supported:
| Version | WebLogic Documentation | 
| ---       | ---     |
| Oracle WebLogic Server 12.2.1.3.0 with patch 29135930 | [documentation](https://docs.oracle.com/middleware/12213/wls/index.html)
| Oracle WebLogic Server 12.2.1.4.0 | [documentation](https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/index.html)
| Oracle WebLogic Server 14.1.1.0.0 | [documentation](https://docs.oracle.com/en/middleware/standalone/weblogic-server/14.1.1.0/)

See the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/userguide/prerequisites/introduction/) 
documentation for more information on supported versions and prerequisites.
 
## Coherence
The supported versions of Coherence are dependent on the Coherence Operator version.
Currently, the following Coherence versions are supported:
| Version | Coherence Documentation | 
| ---       | ---     |
| Oracle Coherence 12.2.1.3 | [documentation](https://docs.oracle.com/middleware/12213/coherence/index.html)
| Oracle Coherence 12.2.1.4 | [documentation](https://docs.oracle.com/en/middleware/fusion-middleware/coherence/12.2.1.4/index.html)
| Oracle Coherence 14.1.1.0 | [documentation](https://docs.oracle.com/en/middleware/fusion-middleware/coherence/12.2.1.4/index.html)

See the [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest/#/about/01_overview) 
documentation for more information.
 
## Helidon
Verrazzano supports all versions of Helidon.  See the [Helidon](https://helidon.io) documentation for more information.

## Installed Components
Verrazzano installs a curated set of open source components.  The following table lists each open source
component with its version and a brief description.

| Component | Version | Description |
| ---       | ---     | ---         |
| cert-manager | 1.2.0 | Automates the management and issuance of TLS certificates.
| Coherence Operator | 3.1.5 | Assists with deploying and managing Coherence clusters.
| Elasticsearch | 7.6.1 | Provides a distributed, multitenant-capable full-text search engine.
| ExternalDNS | 0.7.1 | Synchronizes exposed Kubernetes Services and ingresses with DNS providers.
| Grafana | 6.4.4 | Tool to help you study, analyze, and monitor metrics.
| Istio | 1.7.3 | Service mesh that layers transparently onto existing distributed applications.
| Keycloak | 10.0.1 | Provides single sign-on with Identity and Access Management.
| Kibana | 7.6.1 | Provides search and data visualization capabilities for data indexed in Elasticsearch.
| MySQL | 8.0.20 | Open source relational database management system used by Keycloak.
| NGINX Ingress Controller | 0.46.0 | Traffic management solution for cloud‑native applications in Kubernetes.
| Node Exporter | 1.0.0 | Prometheus exporter for hardware and OS metrics.
| OAM Kubernetes Runtime | 0.3.0 | Plug-in for implementing Open Application Model (OAM) control plane with Kubernetes.
| Prometheus | 2.13.1 | Provides event monitoring and alerting.
| Rancher | 2.5.9 | Manages multiple Kubernetes clusters.
| WebLogic Kubernetes Operator | 3.2.5 | Assists with deploying and managing WebLogic domains.

