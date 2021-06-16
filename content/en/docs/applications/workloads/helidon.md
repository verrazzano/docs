---
title: Helidon Applications
description: Instructions for developing Helidon applications on Verrazzano
linkTitle: Helidon Applications
Weight: 5
draft: true
---
## Helidon Overview

[Helidon](https://helidon.io) is a collection of Java libraries for writing microservices. Helidon provides an open source, 
lightweight, fast, reactive, cloud native framework for developing Java microservices. It is available as two frameworks: 

- [Helidon SE](https://helidon.io/docs/latest/#/se/introduction/01_introduction) is a compact toolkit that embraces the 
  latest Java SE features: reactive streams, asynchronous and functional programming, and fluent-style APIs.
- [Helidon MP](https://helidon.io/docs/latest/#/mp/introduction/01_introduction) implements and supports Eclipse MicroProfile, 
  a baseline platform definition that leverages Java EE and Jakarta EE technologies for microservices and delivers application 
  portability across multiple runtimes.

Helidon is designed and built with container-first philosophy.

- Small footprint, low memory usage and faster startup times.
- All 3rd party dependencies are stored separately to enable Docker layering.
- Provides readiness, liveness and customizable health information for container schedulers like [Kubernetes](https://kubernetes.io/).

Containerized Helidon applications are generally deployed as [`Deployment`](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/) in Kubernetes.

## Verrazzano Integration

Verrazzano supports application definition using [Open Application Model (OAM)](https://oam.dev/). Verrrazzano applications 
are composed of [components](https://github.com/oam-dev/spec/blob/master/3.component.md) and
[application configurations](https://github.com/oam-dev/spec/blob/master/7.application_configuration.md).

Helidon applications are first class citizen in Verrazzano with specialized Helidon Workload support i.e. 
`VerrazzanoHelidonWorkload`. `VerrazzanoHelidonWorkload` is supported as part of `verrazzano-application-operator` in 
Verrazzano install and no additional operator setup or install is required. `VerrazzanoHelidonWorkload` also supports all 
the traits and scopes defined by Verrazzano along with core ones defined by OAM specification.

`VerrazzanoHelidonWorkload` is modeled after [`ContainerizedWorkload`](https://github.com/oam-dev/spec/blob/v0.2.1/core/workloads/containerized_workload/containerized_workload.md)  
i.e. is used for long-running workloads in containers. However, `VerrazzanoHelidonWorkload` closely resembles and directly refers to
Kubernetes [`Deployment`](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/) schema. This
enables easy `Lift and Shift` of existing Containerized Helidon applications. Full `VerrazzanoHelidonWorkload` API 
definition and description is available at [`VerrazzanoHelidonWorkload`](content/en/docs/reference/API/OAM/Workloads.md "VerrazzanoHelidonWorkload")

## Verrazzano Helidon Application Development 
[Application Development Guide](content/en/docs/guides/application-deployment-guide.md) describes end-to-end steps for 
developing and deploying Verrazzano Helidon Application.

For more Verrazzano Helidon Application development examples, please refer to [examples](content/en/docs/examples) section.

## Verrazzano Helidon Application Troubleshooting
Whenever you have a problem with your Verrazzano Helidon Application, there are some basic techniques you 
can use to troubleshoot. [Troubleshooting Guide](content/en/docs/releasenotes/Troubleshooting.md) shows you some simple 
things to try when troubleshooting, as well as how to solve common problems you may encounter.
