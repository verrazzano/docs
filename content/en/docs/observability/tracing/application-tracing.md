---
title: "Understand Application Tracing Components in Verrazzano"
description: "Learn how application tracing components work in Verrazzano"
weight: 1
draft: false
---

Verrazzano provides Jaeger, a distributed tracing system used for monitoring and troubleshooting microservices.

### About distributed tracing
Distributed tracing is a method for tracking application behavior as it propagates through distributed systems.
You can track application requests as they flow from front end devices to back end services and databases.

Distributed tracing is useful for tracking and observability, in general, however, it can also help you identify
the exact line of occurrence of a error in a complex architecture. You can use distributed tracing to troubleshoot
requests that exhibit high latency or errors.

With distributed tracing, the application transactions are captured using request and response headers. A trace header gets added from the original request to subsequent requests and thus creating a link through out the entire transaction that can be traced back to the origin. A single trace typically shows the activity for an individual transaction or request within the application being monitored, from the browser or mobile device, down through to the database and back.

In distributed tracing, a single trace contains a series of tagged time intervals called _spans_. A span can be thought of as a single unit of work. Spans have a start and end time, and optionally may include other metadata, like tags or events. Spans have relationships between one another, including parent-child relationships, which are used to show the specific path a particular transaction takes through the numerous services or components that make up the application.

- A trace represents an end-to-end request; it's made up of a single or multiple spans.
- A span represents work done by a single-service with time intervals and associated metadata, such as tags and events:
   - Tags let you query your traces to filter the results and help with your collaboration and debugging efforts.
   - Events will show up as logs associated with the span that added the event.

### About Jaeger tracing

As with most other distributed tracing systems, Jaeger works with spans and traces, as defined in the [OpenTracing](https://github.com/opentracing/specification/blob/master/specification.md) specification.

In Verrazzano, Jaeger is comprised of the following components:

- Collector service, which receives traces from clients, processes them, and stores them in a storage back end.
- Query service, which exposes the APIs for retrieving traces from storage and hosts the Jaeger console for searching and analyzing traces.
- Storage, may be ephemeral or backed by OpenSearch.
   - Jaeger can be configured to use one of several choices for [storage back ends](https://www.jaegertracing.io/docs/{{<jaeger_doc_version>}}/deployment/#span-storage-backends).
   - In Verrazzano, trace records are stored in OpenSearch; OpenSearch must be enabled in Verrazzano for this to work.

Jaeger is very configurable. See the Jaeger documentation for detailed information about Jaeger [features](https://www.jaegertracing.io/docs/{{<jaeger_doc_version>}}/features/) and [architecture](https://www.jaegertracing.io/docs/{{<jaeger_doc_version>}}/architecture). In Verrazzano, Jaeger does not include the Ingester service, Kafka, or Sparks jobs.

### Next steps

- Enable Jaeger and customize your Verrazzano Jaeger installation. See [configure tracing]({{< relref "/docs/observability/tracing/configure-tracing.md" >}}).
- Configure your applications to [send traces to Jaeger]({{< relref "/docs/observability/tracing/capture-traces.md" >}}).
- Then, use the Verrazzano Jaeger console to [view traces]({{< relref "/docs/observability/tracing/view-traces.md" >}}).
