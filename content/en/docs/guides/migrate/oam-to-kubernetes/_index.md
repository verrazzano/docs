---
title: "OAM to Kubernetes Mappings"
description: "Learn how OAM objects are mapped to Kubernetes objects"
weight: 5
draft: false
---

### Verrazzano CLI export command

Verrazzano provides a CLI command that you can use to facilitate the migration of an OAM application to be managed as a collection of Kubernetes objects.

The command `vz export oam` will output the YAML for each Kubernetes object that was generated as a result of deploying an OAM application.  The generated YAML is sanitized so that it can be used to deploy the application.  Fields such as `creationTimestamp`, `resourceVersion`, `uid`, and `status` are not included in the output.

For example, the following CLI command exports the YAML from the hello-helidon OAM sample application.

{{< clipboard >}}
<div class="highlight">

```
$ vz export oam --name hello-helidon --namespace hello-helidon > myapp.yaml
```
</div>
{{< /clipboard >}}

You can use the output of the command `vz export oam` to deploy the application on another cluster.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace hello-helidon
$ kubectl apply -f myapp.yaml
```
</div>
{{< /clipboard >}}

In addition, you can edit the output of the command `vz export oam` before deploying the application.  The extent to which the exported YAML may be edited will vary based on local requirements. Here are some examples of changes that may be made to the exported YAML:

* The Kubernetes namespace of where to deploy the application
* Add or modify labels or annotations on objects
* Port assignments
* Authorization policies
* Values for secrets
* Mount volume definitions
* Replica counts
* Prometheus logging rules

## Overview of OAM to Kubernetes Mappings

The following documents show the Kubernetes objects generated for each OAM object. They are provided to give you some insight into how each OAM object is converted into one or more Kubernetes objects. However, Oracle recommends that you first start with the output of the `vz export oam` command and then edit the YAML as needed.
