---
title: "Use Fluent-Operator and Fluent-Bit"
linkTitle: Fluent Operator
description: "Configure Fluent-bit using Fluent-Operator"
weight: 2
draft: false
aliases:
- /docs/monitoring/logs
---
Starting from Verrazzano v1.6.0, Fluent-Operator is included as part of our logging stack. When enabled via the Verrazzano custom resource, Fluent-operator is used to configure and manage Fluent-bit, a logging agent which runs as a daemonset.

## Fluent-bit

Fluent-bit is a logging agent that collects, processes, formats and ships logs from kubernetes clusters to log stores.

Using fluent-operator, Verrazzano deploys fluent-bit daemonset which runs one fluent-bit replica per node in the verrazzano-system namespace. Each instance pulls logs from the node's "/var/log/containers" directory and writes them to target OpenSearch data stream.

The four fundamental types of configurations in fluent-bit are:

- Input: to collect data from a source.
- Filter: to process data that was collected.
- Output: to ship logs that was collected and processed to a data store.
- Parser: to parse data in a specific format. Inputs and filters make use of parser configs.

## Fluent-Operator

Verrazzano includes fluent-operator as an optional component. When enabled via the Verrazzano custom resource, the operator is installed in the cluster in the verrazzano-system namespace and creates fluent-bit daemonset in the same namespace using a bunch of custom resources.

To see a list of custom resources that the operator supports to configure fluent-bit, see [fluent-bit resources](https://github.com/verrazzano/fluent-operator#fluent-bit)

All the CRDs with the prefix "Cluster" are cluster-wide configs that can be used to configure all logs coming out of the cluster.

Like cluster-wide resources, the operator comes with namespaced resources which when created will treat logs coming out of the namespace in which these resources exist. The namespaced and cluster-wide configs will run in conjunction and complement each other. Creating a namespaced resource doesn't override an existing cluster-wide resource.

### Enable logging with Fluent-Operator

Verrazzano resource defines two components to configure logging using fluent-operator:

- fluentOperator: When enabled, installs fluent-operator and configures a fluent-bit instance running as a daemonset in the cluster. The fluentOperator component creates ClusterInput CRs of type tail and systemd, and a set of ClusterFilters to enrich the collected logs with kubernetes metadata.
- fluentbitOpensearchOutput: When enabled, creates two ClusterOutput resources to send logs from the cluster to OpenSearch. The two clusteroutputs are:
    - opensearch-system-clusteroutput: A central output sink to send logs coming out of namespaces where the Verrazzano components reside to verrazzano-system data stream in OpenSearch.
    - opensearch-application-clusteroutput: Send logs coming out of namespaces that are not system to verrazzano-application-<namespace_name> data stream.

By default, the above two components are disabled and need to be explicitly enabled in the Verrazzano custom resource. Below is an example of Verrazzano resource manifest with the two components enabled:

```yaml
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
If you already have Verrazzano installation running, then see the steps to [modify installations]({{< relref "/docs/setup/modify-installation#pre-installation" >}}) to enable these two components.

Note that both of the components need to be enabled in order to collect, process and ship logs to OpenSearch.

To get the system and application ClusterOutputs, use the following command:
```bash
$ kubectl get cfbo
```
You should see an opensearch-system-clusteroutput and an opensearch-application-clusteroutput.

### Uninstall Fluentd
Fluentd is the default logging agent which runs as a daemonset that collects, processes and ships logs to log stores. It is installed by default when Verrazzano is installed. With the inclusion of fluent-bit via fluent-operator in our arsenal, you now have an option to run either of these components. These can co-exist, but if your log store is Verrazzano's OpenSearch, and you do not wish to have fluentd running anymore, you can uninstall it via the following Verrazzano resource manifest.
```yaml
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
**NOTE**: Fluent-bit doesn't have the support to ship logs to OCI-Logging. You need to continue using Fluentd if your log store is OCI-Logging.

## Configure custom cluster-wide resources
If you wish to create any cluster-wide resource like a ClusterFilter to filter all of the logs coming out of the cluster in a specific manner or a ClusterOutput such that most of your logs get stored in a custom log store, add the following label under `metadata.labels` of the custom resource manifest

```
fluentbit.fluent.io/enabled: "true"
```

Below is an example of ClusterOutput that sends logs all of the logs coming out of cluster to an OpenSearch index.
```bash
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
Replace <host-url>, <port-number> and <index-name> with appropriate values. The secret holding the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output (i.e. the application namespace). Replace <your-secret-name>, <password-key> and <username-key> with appropriate values.

For any ClusterOutput, create the secret holding the user credentials in the verrazzano-system namespace.

## Configure namespaced resources to process logs for an application namespace
### FluentBitConfig
Fluent-operator supports namespace level configurability that allows a namespace tenant to create fluent-bit configs for logs coming out of their application namespace.

The FluentBitConfig custom resource is a namespaced resource which is used by the fluent-operator to select resources like Filters, Outputs and Parsers via label selectors for the operator from the same namespace as itself. It can also select ClusterParser resource, again via label selectors.

You need to create at-least one FluentBitConfig resource in your namespace should you choose to use namespace level configurability feature of the operator. The FluentBitConfig resource should contain the following label under `metadata.labels`:
```
fluentbit.verrazzano.io/namespace-config: "verrazzano"
```

Below is an example of FluentBitConfig resource to select all filters, outputs and parsers with the label `label: "foo"`.
```bash
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
You can set the labels under `spec.filterSelector`, `spec.parserSelector` and `spec.outputSelector` to any valid label, you just need to create the corresponding Filter, Output and Parser custom resources with that label.

### Filtering and Parsing
Below is an example of a Filter and a Parser to correctly parse logs coming out of a namespace, and FluentBitConfig resource to locate these Filter and Parser resources in the namespace.
```bash
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

### Output
If you're running your own log store, you can create an Output resource in your application namespace such that only the logs coming out of your application namespace go to this log store.

Below is an example of Output resource to ship logs to a custom OpenSearch cluster protected by basic auth:
```bash
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

Replace <host-url>, <port-number> and <index-name> with appropriate values. The secret holding the credentials for the OpenSearch cluster needs to be created in the same namespace as the Output (i.e. the application namespace). Replace <your-secret-name>, <password-key> and <username-key> with appropriate values.

For any namespaced Output, create the secret holding the user credentials in the same namespace as the Output custom resource.

### Disable application log collection in Verrazzano's OpenSearch
The application ClusterOutput created by Verrazzano ensures that the logs for your applications are being shipped to system OpenSearch by default. If you've configured an Output in your application namespace, your application logs will now be stored in two storage, the system OpenSearch via the application ClusterOutput and the custom destination via the Output resource created by you in your application namespace.

If this is not what you intended to do, and you want to opt out of the Verrazzano's OpenSearch log collection, you can disable the application ClusterOutput by editing your Verrazzano custom resource to the following.
```yaml
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
After doing this, you should see that the opensearch-application-clusteroutput is gone. The opensearch-system-clusteroutput will continue to exist and will ship the Verrazzano component logs to Verrazzano's OpenSearch.

## Check Fluent-bit configurations

You can see the generated fluent-bit configuration that the fluent-operator loads in a secret and mounts as a volume in a fluent-bit daemonset.
```bash
$ kubectl -n verrazzano-system get secrets fluent-bit-config -ojson | jq '.data."fluent-bit.conf"' | awk -F '"' '{printf $2}' | base64 --decode
$ $ kubectl -n verrazzano-system get secrets fluent-bit-config -ojson | jq '.data."parsers.conf"' | awk -F '"' '{printf $2}' | base64 --decode
```