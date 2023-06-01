---
title: "Deploy Applications With the Open Application Model"
description: ""
weight: 2
draft: false
---

Developing and deploying applications in [Verrazzano]({{< relref "/" >}}) consists of:
1. Packaging the application as a Docker image.
1. Publishing the application's Docker image to a container registry.
1. Applying the application's Verrazzano components to the cluster.
1. Applying the application's Verrazzano applications to the cluster.

This section does not provide the full details for the first two steps. An existing example application
Docker image has been packaged and published for use.

Verrazzano supports application definition using the [Open Application Model (OAM)](https://oam.dev/).  Verrazzano applications are
composed of [components](https://github.com/oam-dev/spec/blob/master/3.component_model.md) and
[application configurations](https://github.com/oam-dev/spec/blob/master/7.application.md).  This section
demonstrates creating OAM resources that define an application as well as the steps required to deploy those resources.
