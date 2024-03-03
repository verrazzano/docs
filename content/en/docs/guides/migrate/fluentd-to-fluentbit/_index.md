---
title: "Moving to Fluent Bit from Fluentd"
weight: 1
draft: false
---

Fluentd is the default logging agent in Verrazzano, which runs as a DaemonSet that collects, processes, and sends logs to log stores. When Verrazzano is installed, Fluentd is installed by default.
For components with multiple log streams or that cannot log to stdout, Verrazzano deploys a Fluentd sidecar which parses and translates the log stream. The resulting log is sent to stdout of the sidecar container and then written to /var/log/containers by the kubelet service.

In OCNE, the default logging agent will be Fluent Bit, which will be installed via Fluent Operator and will also run as a DaemonSet and operate in a way similar to Fluentd to collect, process and send logs to log stores.
The following sections offer details on how to move to Fluent Bit DaemonSet and sidecar.

Following the migration guide to install and integrate Fluent Bit will result in a Fluent Bit DaemonSet instance that operates similar to Fluentd.

## Migrating Fluentd configuration for Fluentd sidecar to Fluent Bit

Fluent Bit was built on top of Fluentd design and architecture, so they share certain similarities when it comes to configuration and plugins.

For Fluentd to Fluent Bit sidecar migration, follow WKO section.