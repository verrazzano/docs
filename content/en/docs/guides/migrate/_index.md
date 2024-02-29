---
title: "Migrate From Verrazzano to OCNE 2.0"
description: "Learn how to migrate Verrazzano components to OCNE"
weight: 1
draft: false
---

Verrazzano is an enterprise container platform that enables multicloud deployment and management of Kubernetes clusters and container applications that run on those clusters. Verrazzano is a collection of open source Kubernetes-native operators and platform components that are delivered with a single lifecycle with simple installation, configuration, and updates.

Near the end of calendar year 2023, Oracle decided to reduce investment in Verrazzano. As with all businesses, Oracle re-evaluates its investment priorities from time to time. Oracle has decided to focus investment in other areas.

As documented in the [Oracle Lifetime Support Policy: Coverage for Oracle Open Source Service Offerings](https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf), Oracle is committed to providing Premier Support for Oracle Verrazzano 1.x through October 2024. After that time, Oracle will provide Sustaining Support for Oracle Verrazzano, as defined in the [Oracle Lifetime Support Policy](https://www.oracle.com/support/lifetime-support/software.html).

See [My Oracle Support Document 2794708.1](https://support.oracle.com/epmos/faces/DocumentDisplay?id=2794708.1) for specific support dates of Oracle Verrazzano minor versions.

#### Oracle Verrazzano Premier Subscribers

For on-premises customers, you can continue to use Oracle Cloud Native Environment (OCNE), which remains in active development. For cloud customers, Oracle recommends leveraging the cloud-native services available in Oracle Cloud Infrastructure (OCI), including Oracle Container Engine for Kubernetes (OKE), DevOps Service, OCI Search Service with OpenSearch, Application Performance Monitoring, and others.

#### Oracle WebLogic Suite Licensees

For on-premises customers, Oracle recommends use of Oracle Cloud Native Environment (OCNE), which remains in active development. For cloud customers, Oracle recommends moving to Oracle WebLogic Server for OKE on Oracle Cloud Infrastructure (OCI), and leveraging the OCI cloud-native services available, including the services mentioned above.

As part of Oracle WebLogic Server, Oracle provides the [Oracle WebLogic Kubernetes Toolkit](https://oracle.github.io/weblogic-toolkit-ui/), which is a set of open source tools to help you move your WebLogic workloads to containers and Kubernetes. The Oracle WebLogic Kubernetes Toolkit includes the Oracle WebLogic Kubernetes Operator, Oracle WebLogic Deploy Tooling, Oracle WebLogic Monitoring Operator, among others. These tools remain in active development.

#### Migrating to Oracle Cloud Native Environment

[Oracle Cloud Native Environment](https://docs.oracle.com/en/operating-systems/olcne/) (OCNE) is a curated set of open source projects that are based on open standards, specifications and APIs defined by the Open Container Initiative (OCI) and Cloud Native Computing Foundation (CNCF) that can be easily deployed, have been tested for interoperability and for which enterprise-grade support is offered. Oracle Cloud Native Environment delivers a simplified framework for installations, updates, upgrades and configuration of key features for orchestrating microservices. OCNE includes an application catalog that you can use to install platform components in a Kubernetes cluster.

The following sections provide instructions for configuring and integrating key OCNE components as they were configured in Verrazzano.
