---
title: "Welcome to Verrazzano"
linkTitle: "Documentation"
weight: 20
menu:
  main:
    weight: 20
no_list: true
---

Verrazzano is an end-to-end enterprise container platform for deploying cloud-native and traditional applications in multi-cloud and hybrid environments. It is made up of a curated set of open source components – many that you may already use and trust, and some that were written specifically to pull together all of the pieces that make Verrazzano a cohesive and easy to use platform.

**NOTE**: This is an early alpha release of Verrazzano. Some features are still in development. It is suitable for investigation and educational purposes only; it is _not_ suitable for use in production.

Verrazzano includes the following capabilities:

* Hybrid and multi-cluster workload management
* Special handling for WebLogic, Coherence, and Helidon applications
* Multi-cluster infrastructure management
* Integrated and pre-wired application monitoring
* Integrated security
* DevOps and GitOps enablement

{{< alert title="NOTE" color="warning" >}}
This alpha release of Verrazzano is intended for installation in a single
[Oracle Cloud Infrastructure Container Engine for Kubernetes](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) (OKE)
or [Oracle Linux Cloud Native Environment](https://docs.oracle.com/en/operating-systems/olcne/) (OLCNE) cluster.
You should install Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

Select [Quick Start](quickstart) to get started.

Source code is available at [https://github.com/verrazzano/verrazzano](https://github.com/verrazzano/verrazzano).
This repository contains a Kubernetes operator for installing Verrazzano and example applications for use with Verrazzano.
