---
title: "Deploy Applications with Open Application Model"
description: "Learn how to deploy applications with Open Application Model"
weight: 2
draft: false
---

Developing and deploying an application to [Verrazzano]({{< relref "/" >}}) consists of:
1. Packaging the application as a Docker image.
1. Publishing the application's Docker image to a container registry.
1. Applying the application's Verrazzano components to the cluster.
1. Applying the application's Verrazzano applications to the cluster.

This section does not provide the full details for the first two steps. An existing example application
Docker image has been packaged and published for use.

Verrazzano supports application definition using [Open Application Model (OAM)](https://oam.dev/).  Verrrazzano applications are
composed of [components](https://github.com/oam-dev/spec/blob/master/3.component_model.md) and
[application configurations](https://github.com/oam-dev/spec/blob/master/7.application.md).  This document
demonstrates creating OAM resources that define an application as well as the steps required to deploy those resources.
