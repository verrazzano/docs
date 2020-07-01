---
title: "Distributed Tracing"
weight: 7
---

# Introduction

Distributed tracing is a critical feature of microservice-based applications, because it traces 
workflow both within a service and across multiple services.  This provides detailed insight into 
the performance and behavior of your application.  With tracing, you can view sequence and timing 
data for specific blocks of work, along with logs and tags that are recorded in the context of a 
work segment.  This not only helps you identify performance and operational issues, but is also 
extremely useful in problem root cause analysis. 

When you provision an application using Verrazzano, tracing is automatically enabled and ready 
to be used.  However, you will still need to instrument your application to generate trace data, 
as described in [Application Tracing](../../preparing-applications/tracing-apps).

# Tracing Concepts

This section explains a few concepts that are needed to understand tracing. For more details, see
the [OpenTracing Overview](https://opentracing.io/docs/overview/) documentation.

## Jaeger and Zipkin tracers

The OpenTracing component which collects and manages the tracing information is called a _tracer_.  
Two popular tracers are [Jaeger](https://www.jaegertracing.io/) and [Zipkin](https://zipkin.io/). 
Verrazzano installs Istio and automatically enables the Jaeger tracer that Istio provides, so that 
your application can use tracing without any additional Verrazzano setup.  Istio is also configured 
with a Zipkin service, which simply routes the traces to Jaeger.  To view Jaeger tracing data, you 
must forward a Kubernetes port as follows:

```
kubectl -n istio-system port-forward $(kubectl -n istio-system get pod -l app=jaeger -o jsonpath='{.items[0].metadata.name}') 15032:16686
```

Access the Jaeger console at http://localhost:15032/jaeger and you will see the Jaeger home page 
below.  The details will be discussed later.

![Jaeger](../../../images/tracing/jaeger-intro.png)


## Spans
A ```span``` is the basic unit of work done within a single service, on a single host.
Every span has a name, starting timestamp, and duration.  For example, the work done by a REST 
endpoint is a span.  Applications can add information to spans in the form of ```tags```, ```logs```, 
and ```baggage```.  
Tags are key:value pairs that apply to the entire span and can be used to search and filter trace data. 
For example, the http.method tag would let you find spans based on the HTTP method, then you could search 
for the tag http.method="POST".  Logs are point-in-time log messages tied to a span.  Logging in a 
span is extremely useful because you have full context of the log message.  This lets you clearly associate 
logs with the application logic without having to manually correlate them through log files.  Baggage 
is a key:value pair span payload that is propagated to all descendant spans in the span graph, and 
will cross process boundaries as needed.

The figure below shows a span that has both tags and logs.  You can see that the application received 
a POST request, took 557.44 ms to execute, and returned a 200 status.

![Tracing span](../../../images/tracing/span.png)

## Trace structure

Spans are organized as a directed acyclic graph (DAG) and can belong to multiple services, running 
on multiple hosts. Each span is associated with a single service, for example bobbys-front-end, but its 
descendants can belong to different services and hosts.  A ```trace``` is the highest level construct in 
tracing and contains a single span graph, with a single root span. The following figure shows a 
trace with two spans:  ```istio-ingressgateway``` is the root span and ```bobbys-front-end``` is the 
only child span.

![Two spans](../../../images/tracing/spans-two.png)

## Concepts Summary

This section gave a brief description of the basic tracing concepts. In summary, a trace consists of 
a graph of spans, where each span has a duration, tags, logs, and baggage. As applications execute, 
they send span data in a background thread to a tracer, like Jaeger.  You can then use the Jaeger UI 
or API to search or browse the traces that were captured. A trace may consist of spans from multiple 
services and hosts. Refer to the [OpenTracing specification](https://opentracing.io/specification/) 
for more details.


# Using Jaeger to view traces

Let's look at some actual traces that were captured during the execution of the bobby's demo app. 
First, go to bobby's home page at https://{IP}/bobbys-front-end/ and view the following:

![Bobbys home](../../../images/tracing/bobbys-home.png)

Now, look at the trace that was captured by accessing bobby's home page:

![Trace bobbys home](../../../images/tracing/trace-bobbys-home.png)

Notice in the top left column there is a ```Service``` drop-down menu.  A search of service
```bobbys-front-end``` shows a single trace with nine spans, across five services.  A search on
any of those services, like ```istio-ingressgateway``` would find the same trace.

## Trace details

Click on the trace title bar ...

![Trace title-bar bobbys](../../../images/tracing/trace-title-bobbys-home.png)

.. to see the trace details:

![Trace details bobbys](../../../images/tracing/trace-details-bobbys-home.png)

The span tree is displayed in the left column, six levels deep, with the root span being 
```istio-ingressgateway```.  You can clearly see that the ```istio-ingressgateway``` 
service called ```bobbys-front-end```,
which called ```bobbys-helidon-stock-application.bobby.svc.cluster.local:8080/*```, 
and so forth.  The start time of the child span will begin after the start time of the parent, 
but the ending time of a child may extend past the end of the parent span.  This is because the 
parent span might be terminated before the child span.  
In this example, bobbys-stock-app-internal content-write span finished after its parent.  
Notice also that the spans in this trace were
generated by multiple services on multiple hosts.  Furthermore, even though bobby-stock-app-internal 
has child spans, they happen to be in the same service.

By clicking on the individual span, you see the detail span informaiton such as tags and logs

![Span detail bobbys](../../../images/tracing/span-detail-bobbys.png)

## Using traces to triage problems

Tracing is an excellent mechanism to triage and pinpoint problems.  This example intentionally 
generates a database error by inserting data that is too large for the column.  
Specifically, during checkout, too many characters are used in the state field.  Of course, the UI
should prevent this but for tracing purposes, the validation has been relaxed. 

In the bobby's checkout UI, the state field has ```mass``` instead of ```ma```, 
then clicked on the submit button:

![bobbys checkout](../../../images/tracing/bobbys-checkout-mass.png)


When a trace search is done, limiting the output to one trace, the listing shows the checkout trace 
with an error:

![Trace bobbys checkout](../../../images/tracing/trace-bobbys-checkout-error.png)


Drilling down to see the trace detail shows is a span in the bobs-bookstore-order-manager 
service, with a red circle signifying an error.


![Trace bobbys checkout error](../../../images/tracing/trace-details-bobbys-checkout-error.png)

Finally, by examining that span, the root cause of the error is clearly shown as an insert with a 
value too large for a column.  


![Span bobbys checkout error](../../../images/tracing/span-detail-bobbys-checkout-error.png)

Note that the ```error``` tag is set to ```true```.  This is a well-known tag which is recognized by 
Jaeger and allows Jaeger to highlight the error in the UI.  For more information, refer to 
[OpenTracing Semantic Conventions](https://github.com/opentracing/specification/blob/master/semantic_conventions.md)

# Summary

In summary, Verrazzano automatically provides OpenTracing using Istio and Jaeger by default.  
Tracing is a powerful tool that lets you observe and analyze the behavior and performance of your
applications and services.  Tracing is also extremely useful for triaging problems and quickly 
identifying the root cause.  Any Verrazzano application can be easily instrumented to generate traces 
as needed, as discussed in [Enabling Tracing within Applications](../../preparing-applications/tracing). 
