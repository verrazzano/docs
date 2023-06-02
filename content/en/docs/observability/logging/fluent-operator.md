---
title: "Use Fluent Operator and Fluent Bit"
linkTitle: Fluent Operator
description: "Configure Fluent Bit using Fluent Operator"
weight: 2
draft: false
---
From Verrazzano v1.6.0, Fluent Operator is included as part of the logging stack. When enabled, via the Verrazzano custom resource, Fluent Operator configures and manages Fluent Bit, a logging agent that runs as a daemonset.

## Fluent Bit

Fluent Bit is a logging agent that collects, processes, and sends logs from Kubernetes clusters to log stores.

Using Fluent Operator, Verrazzano deploys Fluent Bit daemonset which runs one Fluent Bit replica per node in the verrazzano-system namespace. Each instance reads logs from the node's `/var/log/containers` directory and writes them to a target OpenSearch data store.

The four fundamental types of configurations in Fluent Bit are:

- Input: to collect data from a source.
- Filter: to process data that was collected.
- Output: to send collected and processed logs to a data store.
- Parser: to parse data in a specific format. Inputs and filters make use of parser configs.

## Fluent Operator

Verrazzano includes Fluent Operator as an optional component. When enabled, via the Verrazzano custom resource, the operator is installed in the cluster in the `verrazzano-system` namespace and creates the Fluent Bit daemonset in the same namespace using the required custom resources.

For a list of custom resources that the operator supports to configure Fluent Bit, see [Fluent Bit resources](https://github.com/verrazzano/Fluent Operator#Fluent Bit)

All the CRDs with the prefix _Cluster_ are cluster-wide configurations that can be used to configure all the cluster logs.

Like cluster-wide resources, the operator comes with namespaced resources which when created will process logs from the namespace in which these resources exist. The namespaced and cluster-wide configurations will run in conjunction and complement each other. Creating a namespaced resource doesn't override an existing cluster-wide resource.

### Enable logging with Fluent Operator

Verrazzano resource defines two components to configure logging using Fluent Operator:

- fluentOperator: When enabled, installs Fluent Operator and configures a Fluent Bit instance running as a daemonset in the cluster. The fluentOperator component creates ClusterInput CRs of type tail and systemd, and a set of ClusterFilters to enrich the collected logs with Kubernetes metadata.
- fluentbitOpensearchOutput: When enabled, creates two ClusterOutput resources to send logs from the cluster to OpenSearch. The two clusteroutputs are:
    - opensearch-system-clusteroutput: A central output sink to send logs coming from namespaces where the Verrazzano components reside to the verrazzano-system data stream in OpenSearch.
    - opensearch-application-clusteroutput: Send logs coming from namespaces that are not system to the verrazzano-application-<namespace_name> data stream.

By default, the above two components are disabled and need to be enabled in the Verrazzano custom resource. Following is an example of Verrazzano resource manifest with the two components enabled:

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    fluentOperator:
      enabled: true
    fluentbitOpensearchOutput:
      enabled: true
```
</div>
{{< /clipboard >}}

If Verrazzano is install and running, then to enable these two components see [modify installations]({{< relref "/docs/setup/modify-installation#pre-installation" >}}).

**NOTE**: Both components need to be enabled in order to collect, process, and send logs to OpenSearch.

To get the system and application ClusterOutputs, run the following command:
```bash
$ kubectl get cfbo
```
You should see an opensearch-system-clusteroutput and an opensearch-application-clusteroutput.

### Uninstall Fluentd
Fluentd is the default logging agent which runs as a daemonset that collects, processes, and sends logs to log stores. It is installed by default when Verrazzano is installed. With the inclusion of Fluent Bit via Fluent Operator, you now have an option to run either of these components. These can co-exist, but if your log store is Verrazzano's OpenSearch, and you should uninstall Fluentd as otherwise both components will keep sending same logs to the Verrazzano's OpenSearch resulting into duplicate logs.

**NOTE**: Fluent Bit does not support sending logs to OCI-Logging. Continue using Fluentd if your log store is OCI-Logging.

To uninstall Fluentd use the following Verrazzano resource manifest.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    fluentOperator:
      enabled: true
    fluentbitOpensearchOutput:
      enabled: true
    fluentd:
      enabled: false
```
</div>
{{< /clipboard >}}

## Configure custom cluster-wide resources
If you prefer to create a cluster-wide resource like a `ClusterFilter` to filter all the logs from the cluster in a specific manner or a `ClusterOutput` such that most of the logs get stored in a custom log store, then add the following label under `metadata.labels` of the custom resource manifest.

{{< clipboard >}}
<div class="highlight">

```
fluentbit.fluent.io/enabled: "true"
```
</div>
{{< /clipboard >}}

Following is an example of ClusterOutput that sends logs from a cluster to an OpenSearch index

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: fluentbit.fluent.io/v1alpha2
kind: ClusterOutput
metadata:
  labels:
    fluentbit.fluent.io/enabled: "true"
  name: example-clusteroutput
spec:
  match: *
  opensearch:
    host: <host-url>
    httpPassword:
      valueFrom:
        secretKeyRef:
          key: <password-key>
          name: <your-secret-name>
    httpUser:
      valueFrom:
        secretKeyRef:
          key: <username-key>
          name: <your-secret-name>
    index: <index-name>
    port: <port-number>
    suppressTypeName: true
EOF
```
</div>
{{< /clipboard >}}

Replace _host-url_, _port-number_, and _index-name_ with appropriate values.
Replace _your-secret-name_, _password-key_, and _username-key_ with appropriate values.

For any ClusterOutput, create the secret containing the user credentials in the verrazzano-system namespace.

## Configure custom namespaced resources

You must configure namespaced resources to process logs for an application namespace.

### FluentBitConfig
Fluent Operator supports configurability at the namespace level that allows a user to create Fluent Bit configs for logs from their application namespace.

The FluentBitConfig custom resource is a namespaced resource which is used by the Fluent Operator to select resources like Filters, Outputs, and Parsers via label selectors. These resources will be checked in the same namespace where FluentBitConfig is. It can also select ClusterParser resource, again via label selectors.

If you use namespace level configurability feature of the operator, then you must create a minimum of one FluentBitConfig resource in your namespace. The FluentBitConfig resource should contain the following label under `metadata.labels

{{< clipboard >}}
<div class="highlight">

```
fluentbit.verrazzano.io/namespace-config: "verrazzano"
```
</div>
{{< /clipboard >}}

Following  is an example of FluentBitConfig resource to select all filters, outputs, and parsers with the label `label: "foo"`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    fluentbit.verrazzano.io/namespace-config: "verrazzano"
  name: example-fluentbitconfig
  namespace: <application-namespace>
spec:
  filterSelector:
    matchLabels:
      foo: "bar"
  parserSelector:
    matchLabels:
      foo: "bar"
  outputSelector:
    matchLabels:
      foo: "bar"
EOF
```
</div>
{{< /clipboard >}}

You can set the labels under `spec.filterSelector`, `spec.parserSelector` and `spec.outputSelector` to any valid label, you just need to create the corresponding Filter, Output and Parser custom resources with that label.

### Custom Filtering and Parsing
Following is an example of a Filter and a Parser to parse logs from myapp application running in my-app namespace, and FluentBitConfig resource to locate these Filter and Parser resources in the same namespace where logs emitted by it have the following format:
```text
2023-05-29T09:53:35.959135345Z stdout F 2023-05-29 09:53:35 +0000 [warn]: #0 got incomplete line before first line from /logs/myapp-0.log: "(thread=DefaultHttpServerThread-1, member=3, up=342.673): Health: checking safe\n"
```
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
-----
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    fluentbit.verrazzano.io/namespace-config: "verrazzano"
  name: myapp-fluentbitconfig
  namespace: my-app
spec:
  filterSelector:
    matchLabels:
      app: "myapp"
  parserSelector:
    matchLabels:
      app: "myapp"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    app: "myapp"
  name: myapp-filter
  namespace: my-app
spec:
  filters:
  - parser:
      keyName: log
      reserveData: true
      parser: myapp-parser
  match: kube.*
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:       
    app: "myapp"
  name: myapp-parser
  namespace: my-app
spec:
  regex:
    regex: '/^(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z) (?<level>[^\s]+)[^:]+: (?<message>.*)$/'
    timeFormat: '%Y-%m-%dT%H:%M:%S.%LZ'
    timeKey: logtime
EOF
```
</div>
{{< /clipboard >}}

This configuration consists of three resources: FluentBitConfig, Filter, and Parser.

FluentBitConfig:
  - Name: myapp-fluentbitconfig
  - Namespace: my-app
  - It uses a filterSelector and parserSelector to match labels with the value "myapp" for accurate filtering and parsing.

Filter:
 - Name: myapp-filter
 - Namespace: my-app
 - This filter is associated with the "myapp" application.
 - It applies a parser called "myapp-parser" to the logs and filter is configured to match logs from the "kube" source.

Parser:
 - Name: myapp-parser
 - Namespace: my-app
 - This parser defines the regular expression and formatting details for parsing logs. It extracts three fields from the log lines: logtime, level, and message.

After applying this configuration, you should observe that the logs emitted by the "myapp" application are now parsed according to the regex and enriched with the following fields:
```
level: stderr
logtime: 2023-05-29T09:53:35.959135345Z
message: Health: checking safe
```
You can adjust the provided regular expression (regex) in the Parser resource according to the specific format of your logs. Modify it to match the structure and patterns of your application's log lines.

### Custom Output
If you are running your own log store, you can create an Output resource in your application namespace so that only the logs from your application namespace go to this log store.

Following is an example of Output resource for myapp application running in my-app namespace to send logs to a custom OpenSearch cluster protected by basic authentication:

{{< clipboard >}}
<div class="highlight">

```
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    fluentbit.verrazzano.io/namespace-config: "verrazzano"
  name: myapp-fluentbitconfig
  namespace: my-app
spec:
  outputSelector:
    matchLabels:
      app: "myapp"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Output
metadata:
  labels:
    app: "myapp"
  name: myapp-output
  namespace: my-app
spec:
  match: kube.*
  opensearch:
    host: <host-url>
    httpPassword:
      valueFrom:
        secretKeyRef:
          key: <password-key>
          name: <your-secret-name>
    httpUser:
      valueFrom:
        secretKeyRef:
          key: <username-key>
          name: <your-secret-name>
    index: <index-name>
    port: <port-number>
    suppressTypeName: true
EOF
```
</div>
{{< /clipboard >}}

Replace _host-url_, _port-number_ and _index-name_ with appropriate values. The secret holding the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output, that is, the application namespace. Replace _your-secret-name_, _password-key_ and _username-key_ with appropriate values.

For any namespaced Output resources, the secret containing the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output, that is, the application namespace.

Note that with this configuration, your applications logs will still continue to go to deafult cluster output as well.

### Disable application log collection in Verrazzano's OpenSearch

The application ClusterOutput created by Verrazzano ensures that, by default, the logs for your applications are sent to the system OpenSearch. If you have configured an Output in your application namespace, your application logs will now be stored in two storages, the system OpenSearch via the application ClusterOutput and the custom destination via the Output resource created by you in your application namespace.

If you want to opt out of the Verrazzano's OpenSearch log collection, you can disable the application ClusterOutput by editing your Verrazzano custom resource as follows.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    fluentOperator:
      enabled: true
    fluentbitOpensearchOutput:
      enabled: true
      overrides:
        - values:
            application:
              enabled: false
```
</div>
{{< /clipboard >}}

After updating your Verrazzano custom resource, you can notice that the opensearch-application-clusteroutput ClusterOutput resource will be removed from the verrazzano-logging namespace. The opensearch-system-clusteroutput will continue to exist and will send the Verrazzano component logs to Verrazzano's OpenSearch.

## Check Fluent Bit configurations

You can view the generated Fluent Bit configuration that the Fluent Operator loads in a secret and mounts as a volume in a Fluent Bit daemonset.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n verrazzano-system get secrets Fluent Bit-config -ojson | jq '.data."Fluent Bit.conf"' | awk -F '"' '{printf $2}' | base64 --decode
$ $ kubectl -n verrazzano-system get secrets Fluent Bit-config -ojson | jq '.data."parsers.conf"' | awk -F '"' '{printf $2}' | base64 --decode
```
</div>
{{< /clipboard >}}
