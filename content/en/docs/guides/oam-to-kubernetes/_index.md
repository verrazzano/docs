---
title: "OAM to Kubernetes Mappings"
description: "Learn how OAM objects are mapped to Kubernetes objects"
weight: 5
draft: false
---

### Verrazzano CLI export command

Verrazzano provides a CLI option that you can use to facilitate the migration of an OAM application to be managed as a collection of Kubernetes objects.

The command `vz export oam` will output the YAML for each Kubernetes resource that was generated as a result of deploying an OAM application.  The generated YAML is sanitized so that it can be used to deploy the application.  Fields such as `creationTimestamp`, `resourceVersion`, `uid`, and `status` are not included in the  output.

For example, the following CLI command exports the YAML from the hello-helidon OAM sample application.

{{< clipboard >}}
<div class="highlight">

```
$ vz export oam --name hello-helidon --namespace hello-helidon > myapp.yaml
```
</div>
{{< /clipboard >}}

## Overview of OAM to Kubernetes Mappings

The following documents show the Kubernetes resources generated for each OAM resource.
