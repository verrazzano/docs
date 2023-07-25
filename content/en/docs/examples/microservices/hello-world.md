---
title: "Hello World Helidon"
weight: 2
aliases:
  - /docs/samples/hello-world
---

The Hello World Helidon example is a [Helidon](https://helidon.io)-based service that returns a "Hello World" response when invoked. The example application is specified using Open Application Model (OAM) component and application configuration YAML files, and then deployed by applying those files.

The example application has two endpoints, which differ in configuration source:
* `/greet`- uses a microprofile properties file. Deploy this application by using the instructions [here]({{< relref "/docs/examples/hello-helidon/_index.md" >}}).
* `/config`- uses a Kubernetes ConfigMap. Deploy this application by using the instructions [here]({{< relref "/docs/examples/helidon-config/_index.md" >}}).


For more information and the code of this application, see the [Verrazzano examples](https://github.com/verrazzano/examples).
