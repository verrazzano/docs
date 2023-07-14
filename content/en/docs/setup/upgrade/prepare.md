---
title: "Prepare to Upgrade Verrazzano"
description: "Pre-upgrade information"
weight: 1
draft: false
---

A Verrazzano installation consists of a stack of components, such as cert-manager, where each component has a
specific release version that may be different from the overall Verrazzano version.  The Verrazzano platform operator
knows the versions of each component associated with the Verrazzano version.  When you perform the initial Verrazzano
installation, the appropriate version of each component is installed by the platform operator.
Post installation, it may be necessary to update one or more of the component images or Helm charts.  This update is also
handled by the platform operator and is called an `upgrade`.  Currently, Verrazzano does only patch-level upgrades,
where a `helm upgrade` command can be issued for the component.  Typically, patch-level upgrades simply replace component
images with newer versions.

### Application and system pod restarts
If Verrazzano has a new version of Istio, then all the pods with Istio proxy sidecars
need to be restarted. This is done so that the new version of the proxy sidecar can be injected into the pods.
All Verrazzano system pods containing Istio proxy sidecars will be restarted.
Additionally, OAM application workloads with old versions of the Istio proxy sidecar will be restarted as well.
Verrazzano will perform a rolling restart of all OAM workloads except WebLogic workloads with an Istio proxy sidecar
that is out of date by two minor version or more. For these workloads, Verrazzano will stop the WebLogic Domain prior to upgrade
and restart it once the upgrade has been completed. This may result in downtime during upgrade for these WebLogic workloads.
There is no user involvement related to restarting OAM applications; it is done automatically during upgrade.
