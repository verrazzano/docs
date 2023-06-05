---
title: "View Trace Records"
description: "View trace records in the Jaeger console"
weight: 5
draft: false
---

Use the Verrazzano Jaeger console to view, query, and filter traces.
For information on how to get the Verrazzano Jaeger console URL and credentials, see [Access Verrazzano]({{< relref "/docs/setup/access/" >}}).

### View traces in the Jaeger console

On the initial page, select the service name to display the traces that you want to evaluate, for example, `hello-helidon`.

![Hello Helidon](/docs/images/tracing/hello-helidon-traces.png)

Select a trace to see its details.

![Hello Helidon SPAN](/docs/images/tracing/hello-helidon-spans.png)

To filter the number of responses, add a filtering option by specifying a tag element to be a part of the search criteria.

The Jaeger console shows:

- All the spans that make up the trace.
- Each span will contain all the tags, events, and timings for that span.
- Each span can be expanded to see the values of the tags, events, and the start time, end time, and the overall duration of the span.


### View managed cluster traces

You can see the managed cluster traces from the Jaeger console in the admin cluster only. To find the Jaeger console URL for
your admin cluster, follow the instructions for [Accessing Verrazzano]({{< relref "/docs/setup/access/_index.md" >}}).

The following spans include the Process tag, `verrazzano_cluster`, which has the name of the managed cluster. To see the traces
for the managed cluster only, search based on the tag `verrazzano_cluster=<managed cluster name>`.

**Sample output of Jager console screens**

Output filtered for the managed cluster, `managed1` (arrow).

![Jaeger console](/docs/images/multicluster/jaeger-multicluster-filter-based-on-tag.png)

The span details for `managed1`.

![Jaeger SPAN](/docs/images/multicluster/jaeger-multicluster-span-details.png)

### Store traces and log records

In Verrazzano, all the Jaeger traces are stored in OpenSearch; OpenSearch must be enabled in Verrazzano for this to work.
The logs are also captured and stored in OpenSearch; this is done by Fluentd.

Read the blog, [Jaeger, Fluentd, and OpenSearch with Verrazzano](https://medium.com/verrazzano/the-verrazzano-platform-includes-several-cloud-native-solutions-to-improve-an-enterprises-day-2-25212f01f5cc) for a detailed look at how Verrazzano components work together to provide a complete observability stack.
