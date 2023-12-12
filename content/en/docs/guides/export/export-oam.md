---
title: "Export the Kubernetes objects that were generated for an OAM application"
linkTitle: "OAM to Kubernetes Mappings"
description: "A guide for understanding how OAM objects are mapped to Kubernetes objects"
weight: 5
draft: false
---

This guide provides an overview of how an OAM application that is deployed by Verrazzano becomes a set of Kubernetes resources.

## Verrazzano CLI Export Command

Verrazzano provides a CLI option that can be used to facilitate the migration of an OAM application to be managed as a set of Kubernetes objects.  

The command `vz export oam` will output the YAML for each Kubernetes resource that was generated as a result of deploying an OAM application.  The generated YAML is sanitized so that it could be re-applied.  For example, fields such as `creationTimestamp`, `resourceVersion`, `uid`, and `status` are not included in the  output.

For example, using the Verrazzano CLI to export the YAML for the hello-helidon OAM sample application:

{{< clipboard >}}
<div class="highlight">

```
vz export oam --name hello-helidon --namespace hello-helidon > myapp.yaml
```
</div>
{{< /clipboard >}}
