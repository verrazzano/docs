---
title: "Use Fluent-Operator and Fluent-Bit"
linkTitle: Fluent Operator
description: "Configure Fluent-bit using Fluent-Operator"
weight: 2
draft: false
---
From Verrazzano v1.6.0, Fluent-Operator is included as part of the logging stack. When enabled, via the Verrazzano custom resource, Fluent-operator configures and manages Fluent-bit, a logging agent that runs as a daemonset.

## Fluent-bit

Fluent-bit is a logging agent that collects, processes, and sends logs from Kubernetes clusters to log stores.

Using fluent-operator, Verrazzano deploys Fluent-bit daemonset which runs one Fluent-bit replica per node in the verrazzano-system namespace. Each instance pulls logs from the node's `/var/log/containers` directory and writes them to target OpenSearch data stream.

The four fundamental types of configurations in Fluent-bit are:

- Input: to collect data from a source.
- Filter: to process data that was collected.
- Output: to send collected and processed logs to a data store.
- Parser: to parse data in a specific format. Inputs and filters make use of parser configs.

## Fluent-Operator

Verrazzano includes fluent-operator as an optional component. When enabled, via the Verrazzano custom resource, the operator is installed in the cluster in the `verrazzano-system` namespace and creates the Fluent-bit daemonset in the same namespace using the required custom resources.

For a list of custom resources that the operator supports to configure Fluent-bit, see [Fluent-bit resources](https://github.com/verrazzano/fluent-operator#fluent-bit)

All the CRDs with the prefix _Cluster_ are cluster-wide configurations that can be used to configure all the cluster logs.

Like cluster-wide resources, the operator comes with namespaced resources which when created will process logs from the namespace in which these resources exist. The namespaced and cluster-wide configurations will run in conjunction and complement each other. Creating a namespaced resource doesn't override an existing cluster-wide resource.

### Enable logging with Fluent-Operator

Verrazzano resource defines two components to configure logging using fluent-operator:

- fluentOperator: When enabled, installs fluent-operator and configures a Fluent-bit instance running as a daemonset in the cluster. The fluentOperator component creates ClusterInput CRs of type tail and systemd, and a set of ClusterFilters to enrich the collected logs with Kubernetes metadata.
- fluentbitOpensearchOutput: When enabled, creates two ClusterOutput resources to send logs from the cluster to OpenSearch. The two clusteroutputs are:
    - opensearch-system-clusteroutput: A central output sink to send logs coming out of namespaces where the Verrazzano components reside to verrazzano-system data stream in OpenSearch.
    - opensearch-application-clusteroutput: Send logs coming out of namespaces that are not system to verrazzano-application-<namespace_name> data stream.

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
Fluentd is the default logging agent which runs as a daemonset that collects, processes, and sends logs to log stores. It is installed by default when Verrazzano is installed. With the inclusion of Fluent-bit via fluent-operator, you now have an option to run either of these components. These can co-exist, but if your log store is Verrazzano's OpenSearch, and you can uninstall Fluentd.

**NOTE**: Fluent-bit does not support sending logs to OCI-Logging. Continue using Fluentd if your log store is OCI-Logging.

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
The secret containing the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output, that is, the application namespace. Replace _your-secret-name_, _password-key_, and _username-key_ with appropriate values.

For any ClusterOutput, create the secret containing the user credentials in the verrazzano-system namespace.

## Configure namespaced resources

You must configure namespaced resources to process logs for an application namespace.

### FluentBitConfig
Fluent-operator supports configurability at the namespace level that allows a namespace tenant to create Fluent-bit configs for logs from their application namespace.

The FluentBitConfig custom resource is a namespaced resource which is used by the fluent-operator to select resources like Filters, Outputs, and Parsers via label selectors for the operator from the same namespace as itself. It can also select ClusterParser resource, again via label selectors.

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

### Filtering and Parsing
Following is an example of a Filter and a Parser to parse logs from a namespace, and FluentBitConfig resource to locate these Filter and Parser resources in the namespace.

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
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    foo: "bar"
  name: example-filter
  namespace: <application-namespace>
spec:
  filters:
  - parser:
      keyName: log
      reserveData: true
      parser: example-parser
  match: kube.*
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:       
    foo: "bar"
  name: example-parser
  namespace: <application-namespace>
spec:
  regex:
    regex: '/^.*?(?<logtime>\d{2}:\d{2}:\d{2},\d{3}) (?<level>.*?)( |\t)+\[.*?\]( |\t)+\(.*?\)( |\t)+(?<message>.*)$/'
    timeKey: logtime
    timeFormat: "%H:%M:%S,%N"
EOF
```
</div>
{{< /clipboard >}}

### Output
If you are running your own log store, you can create an Output resource in your application namespace so that only the logs from your application namespace go to this log store.

Following is an example of Output resource to send logs to a custom OpenSearch cluster protected by basic authentication:

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
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Output
metadata:
  labels:
    foo: "bar"
  name: example-output
  namespace: <application-namespace>
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

For any namespaced Output, create the secret containing the user credentials in the same namespace as the Output custom resource.

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
    fluentbitOpensearch:
      enabled: true
      overrides:
        - values:
            application:
              enabled: false
```
</div>
{{< /clipboard >}}

After updating your Verrazzano custom resource, you can notice that the opensearch-application-clusteroutput is removed. The opensearch-system-clusteroutput will continue to exist and will send the Verrazzano component logs to Verrazzano's OpenSearch.

## Check Fluent-bit configurations

You can view the generated Fluent-bit configuration that the fluent-operator loads in a secret and mounts as a volume in a fluent-bit daemonset.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n verrazzano-system get secrets fluent-bit-config -ojson | jq '.data."fluent-bit.conf"' | awk -F '"' '{printf $2}' | base64 --decode
$ $ kubectl -n verrazzano-system get secrets fluent-bit-config -ojson | jq '.data."parsers.conf"' | awk -F '"' '{printf $2}' | base64 --decode
```
</div>
{{< /clipboard >}}
