---
title: "Use Fluent Operator and Fluent Bit"
linkTitle: Fluent Operator
description: "Configure Fluent Bit using Fluent Operator"
weight: 2
draft: false
---
Beginning in v1.6.0, Fluent Operator is included in the logging stack and when enabled, the Fluent Operator configures and manages Fluent Bit, a logging agent that runs as a DaemonSet.

## Fluent Bit

Fluent Bit is a logging agent that collects, processes, and sends logs from Kubernetes clusters to log stores.

Using Fluent Operator, Verrazzano deploys the Fluent Bit DaemonSet, which runs one Fluent Bit replica per node in the `verrazzano-system` namespace. Each instance reads logs from the node's `/var/log/containers` directory and writes them to a target OpenSearch data store.

The four fundamental types of configurations in Fluent Bit are:

- Input: to collect data from a source.
- Filter: to process data that was collected.
- Output: to send collected and processed logs to a data store.
- Parser: to parse data in a specific format. Inputs and filters make use of parser configurations.

## Fluent Operator

Verrazzano includes Fluent Operator as an optional component. When [enabled](#enable-logging-with-fluent-operator), the operator is installed in the cluster in the `verrazzano-system` namespace and creates the Fluent Bit DaemonSet in the same namespace, using the required custom resources.

For a list of custom resources that the operator supports to configure Fluent Bit, see [Fluent Bit resources](https://github.com/verrazzano/fluent-operator#fluent-bit).

All the CRDs with the prefix _Cluster_ are cluster-wide configurations that you can use to configure all the cluster logs.

Like cluster-wide resources, the operator comes with namespaced resources, which when created will process logs from the namespace in which these resources exist. The namespaced and cluster-wide configurations will run in conjunction and complement each other. Creating a namespaced resource doesn't override an existing cluster-wide resource.

### Enable logging with Fluent Operator

The Verrazzano resource defines two components to configure logging using Fluent Operator:

- `fluentOperator`: When enabled, installs Fluent Operator and configures a Fluent Bit instance running as a DaemonSet in the cluster. The `fluentOperator` component creates ClusterInput CRs of type tail and systemd, and a set of ClusterFilters to enrich the collected logs with Kubernetes metadata.
- `fluentbitOpensearchOutput`: When enabled, creates two ClusterOutput resources to send logs from the cluster to OpenSearch. The two ClusterOutput resources are:
    - `opensearch-system-clusteroutput`: A central output sink to send logs coming from namespaces where the Verrazzano components reside to the `verrazzano-system` data stream in OpenSearch.
    - `opensearch-application-clusteroutput`: Sends logs coming from namespaces that are not system to the `verrazzano-application-<namespace_name>` data stream.

By default, these two components are disabled and must be enabled in the Verrazzano custom resource. The following is an example of a Verrazzano resource manifest file with the two components enabled.

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

If Verrazzano is installed and running, then to enable these two components, see [Modify Verrazzano Installations]({{< relref "/docs/setup/modify-installation#post-installation" >}}).

**NOTE**: To collect, process, and send logs to OpenSearch, _both_ components must be enabled.

To get the system and application ClusterOutput resources, run the following command:
```bash
$ kubectl get cfbo
```
You will see an `opensearch-system-clusteroutput` and an `opensearch-application-clusteroutput`.

### Uninstall Fluentd
Fluentd is the default logging agent, which runs as a DaemonSet that collects, processes, and sends logs to log stores. When Verrazzano is installed, it is installed by default. With the inclusion of Fluent Bit via the Fluent Operator, you now have the option to run either of these components. These two, Fluentd and Fluent Bit, can co-exist, but if your log store is Verrazzano OpenSearch, then you should uninstall Fluentd because both components will send the same logs to Verrazzano OpenSearch, resulting in duplicate logs.

**NOTE**: Fluent Bit does not support sending logs to OCI-Logging. If your log store is OCI-Logging, then continue using Fluentd.

To uninstall Fluentd, use the following Verrazzano resource manifest file.
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
If you prefer to create a cluster-wide resource, like a `ClusterFilter`, to filter all the logs from the cluster in a specific manner, or a `ClusterOutput`, such that most of the logs get stored in a custom log store, then add the following label under `metadata.labels` of the custom resource manifest file.

{{< clipboard >}}
<div class="highlight">

```
fluentbit.fluent.io/enabled: "true"
```
</div>
{{< /clipboard >}}

The following is an example of ClusterOutput that sends logs from a cluster to an OpenSearch index.

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

- Replace `<host-url>`, `<port-number>`, and `<index-name>` with the appropriate values.
- Replace `<your-secret-name>`, `<password-key>`, and `<username-key>` with the appropriate values.

For any ClusterOutput, create the secret containing the user credentials in the `verrazzano-system` namespace.

## Configure custom namespaced resources

You must configure namespaced resources to process logs for an application namespace.

### FluentBitConfig
The Fluent Operator supports configurability at the namespace level that lets you create Fluent Bit configurations for logs from your application namespace.

The FluentBitConfig custom resource is a namespaced resource, which is used by the Fluent Operator to select resources, like Filters, Outputs, and Parsers using label selectors. These resources will be checked in the same namespace as FluentBitConfig. Using label selectors, it can also select ClusterParser resources.

If you use the namespace-level configurability feature of the operator, then you must create a minimum of one FluentBitConfig resource in your namespace. The FluentBitConfig resource should contain the following label under `metadata.labels`.

{{< clipboard >}}
<div class="highlight">

```
fluentbit.verrazzano.io/namespace-config: "verrazzano"
```
</div>
{{< /clipboard >}}

The following  is an example of a FluentBitConfig resource to select all Filters, Outputs, and Parsers with the label, `label: "foo"`.

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

You can set the labels under `spec.filterSelector`, `spec.parserSelector`, and `spec.outputSelector` to any valid label; you just need to create the corresponding Filter, Output and Parser custom resources with that label.

### Custom filtering and parsing
The following is an example of a Filter and a Parser to parse logs from the `myapp` application, running in the `my-app` namespace, and a FluentBitConfig resource to locate these Filter and Parser resources in the same namespace, where logs emitted have the following format:
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
  - Name: `myapp-fluentbitconfig`
  - Namespace: `my-app`
  - For accurate filtering and parsing, it uses a filterSelector and parserSelector to match labels with the value `myapp`.

Filter:
 - Name: `myapp-filter`
 - Namespace: `my-app`
 - This filter is associated with the `myapp` application.
 - It applies a parser, called `myapp-parser`, to the logs and the filter is configured to match logs from the `kube` source.

Parser:
 - Name: `myapp-parser`
 - Namespace: `my-app`
 - This parser defines the regular expression and formatting details for parsing logs. It extracts three fields from the log lines: `logtime`, `level`, and `message`.

After applying this configuration, you will observe that the logs emitted by the `myapp` application are now parsed according to the regex and enriched with the following fields:
```
level: stderr
logtime: 2023-05-29T09:53:35.959135345Z
message: Health: checking safe
```
You can adjust the provided regular expression (regex) in the Parser resource according to the specific format of your logs. Modify it to match the structure and patterns of your application's log lines.

### Custom output
If you are running your own log store, then you can create an Output resource in your application namespace, so that only the logs from your application namespace go to this log store.

The following is an example of an Output resource for the `myapp` application, running in the `my-app` namespace, to send logs to a custom OpenSearch cluster, protected by basic authentication.

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

- Replace `<host-url>`, `<port-number>`, and `<index-name>` with the appropriate values. The secret holding the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output, that is, the application namespace.
- Replace `<your-secret-name>`, `<password-key>`, and `<username-key>` with the appropriate values.

For any namespaced Output resources, the secret containing the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output, that is, the application namespace.

Note that with this configuration, your applications logs still will continue to go to the default cluster output as well.

### Disable application log collection in Verrazzano OpenSearch

By default, the application ClusterOutput created by Verrazzano ensures that the logs for your applications are sent to the system OpenSearch. If you have configured an Output in your application namespace, your application logs will now be stored in two locations, the system OpenSearch, by using the application ClusterOutput and the custom destination, by using the Output resource you created in your application namespace.

If you want to opt out of the Verrazzano OpenSearch log collection, you can disable the application ClusterOutput by editing your Verrazzano custom resource as follows:

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

After updating your Verrazzano custom resource, you will notice that the `opensearch-application-clusteroutput` ClusterOutput resource will be removed from the cluster. The `opensearch-system-clusteroutput` will continue to exist and will send the Verrazzano component logs to Verrazzano OpenSearch.


## Configure the systemd logs directory

By default, the systemd journal logs directory is set to `/var/run/journal`. However, depending on the environment, the directory location may vary.

To override the default configuration and set the logs directory to a different path, edit your Verrazzano custom resource as follows:
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
      overrides:
        - values:
            fluentbit:
              input:
                systemd:
                  path: <new-path>
    fluentbitOpensearchOutput:
      enabled: true
```
</div>
{{< /clipboard >}}

## Check Fluent Bit configurations

View the generated Fluent Bit configuration that the Fluent Operator loads in a secret and mounts as a volume in a Fluent Bit DaemonSet, as follows:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl -n verrazzano-system get secrets Fluent Bit-config -ojson | jq '.data."fluent-bit.conf"' | awk -F '"' '{printf $2}' | base64 --decode
$ kubectl -n verrazzano-system get secrets Fluent Bit-config -ojson | jq '.data."parsers.conf"' | awk -F '"' '{printf $2}' | base64 --decode
```
</div>
{{< /clipboard >}}
