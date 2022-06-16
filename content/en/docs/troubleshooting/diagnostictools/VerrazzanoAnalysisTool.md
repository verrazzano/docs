---
title: Verrazzano Analysis Tools
linkTitle: Verrazzano Analysis Tools
weight: 1
description: Use the Verrazzano Analysis Tools to analyze cluster dumps
draft: false
---


Verrazzano provides tooling which assists in troubleshooting issues in your environment:
1. `k8s-dump-cluster.sh`
2. `verrazzano-analysis`

## Tools Setup
These tools are available for Linux and Mac: https://github.com/verrazzano/verrazzano/releases/.

{{< tabs tabTotal="2" >}}
{{< tab tabName="Linux" >}}
<br>

### Linux Instructions

Use these instructions to obtain the analysis tools on Linux machines.  

#### Download the tooling
  ```
   $ wget {{<release_asset_url k8s-dump-cluster.sh>}}
   $ wget {{<release_asset_url k8s-dump-cluster.sh.sha256>}}
   $ wget {{<release_asset_url verrazzano-analysis-linux-amd64.tar.gz>}}
   $ wget {{<release_asset_url verrazzano-analysis-linux-amd64.tar.gz.sha256>}}
  ```

#### Verify the downloaded files
  ```
   $ sha256sum -c k8s-dump-cluster.sh.sha256
   $ sha256sum -c verrazzano-analysis-linux-amd64.tar.gz.sha256
  ```

#### Unpack the `verrazzano-analysis` binary
  ```
   $ tar xvf verrazzano-analysis-linux-amd64.tar.gz
  ```
{{< /tab >}}
{{< tab tabName="macOS" >}}
<br>

### Mac Instructions

Use these instructions to obtain the analysis tools on Mac machines.

#### Download the tooling
  ```
   $ wget {{<release_asset_url k8s-dump-cluster.sh>}}
   $ wget {{<release_asset_url k8s-dump-cluster.sh.sha256>}}
   $ wget {{<release_asset_url verrazzano-analysis-darwin-amd64.tar.gz>}}
   $ wget {{<release_asset_url verrazzano-analysis-darwin-amd64.tar.gz.sha256>}}
  ```
#### Verify the downloaded files
  ```
   $ shasum -a 256 -c k8s-dump-cluster.sh.sha256
   $ shasum -a 256 -c verrazzano-analysis-darwin-amd64.tar.gz.sha256
  ```

#### Unpack the `verrazzano-analysis` binary
  ```
   $ tar xvf verrazzano-analysis-darwin-amd64.tar.gz
  ```

{{< /tab >}}
{{< /tabs >}}


## Use the `k8s-dump-cluster.sh` tool

The `k8s-dump-cluster.sh` tool is a shell script which runs various `kubectl` and `helm` commands against a cluster.

Note that the data captured by this script might include sensitive information. This data is under your control; you can choose whether to share it.

The directory structure created by the `k8s-dump-cluster.sh` tool, for a specific cluster dump, appears as follows:

    $ CAPTURE_DIR
      cluster-dump
        directory per namespace (a directory at this level is assumed to represent a namespace)
          acme-orders.json
          application-configurations.json
          certificate-requests.json
          cluster-role-bindings.json
          cluster-roles.json
          cluster-roles.json
          coherence.json
          components.json
          {CONFIGNAME}.configmap (a file at this level for each configmap in the namespace)
          daemonsets.json
          deployments.json
          events.json
          gateways.json
          ingress-traits.json
          jobs.json
          multicluster-application-configurations.json
          multicluster-components.json
          multicluster-config-maps.json
          multicluster-logging-scopes.json
          multicluster-secrets.json
          namespace.json
          persistent-volume-claims.json
          persistent-volumes.json
          pods.json
          replicasets.json
          replication-controllers.json
          role-bindings.json
          services.json
          verrazzano-managed-clusters.json
          verrazzano-projects.json
          virtualservices.json
          weblogic-domains.json
          directory per pod (a directory at this level is assumed to represent a specific pod)
            logs.txt (includes logs for all containers and initContainers)
        cluster-issuers.txt
        configmap_list.out
        crd.json
        es_indexes.out
        helm-ls.json
        helm-version.out
        images-on-nodes.csv
        ingress.json
        kubectl-version.json
        network-policies.json
        network-policies.txt
        nodes.json
        pv.json
        verrazzano_resources.json

The script shows the `kubectl` and `helm` commands which are run. The basic structure, shown previously, is formed by running the command, `$ kubectl cluster-info dump --all-namespaces`, with additional data captured into that directory structure.

To perform a dump of a cluster into a directory named `my-cluster-dump`:

`$ sh k8s-dump-cluster.sh -d my-cluster-dump`

## Use the `verrazzano-analysis` tool

The `verrazzano-analysis` tool analyzes data from a cluster dump captured using `k8s-dump-cluster.sh`, reports the issues found, and prescribes related actions to take.  These tools are continually evolving with regard to what may be captured, the knowledge base of issues and actions, and the types of analysis that can be performed.

Users, developers, and Continuous Integration (CI) can use this tooling to quickly identify the root cause of encountered problems, determine mitigation actions, and provide a sharable report with other users or tooling.

The data that the analysis examines follows the structure created by the corresponding capture tooling. For example, `k8s-dump-cluster.sh` dumps a cluster into a specific structure, which might contain data that you do not want to share. The tooling analyzes the data and provides you with a report, which identifies issues and provides you with actions to take.

The `verrazzano-analysis` tool will find and analyze all cluster dump directories found under a specified root directory. This lets you create a directory to hold the cluster dumps of related clusters into sub-directories which the tool can analyze.

For example:

    my-cluster-dumps
        CAPTURE_DIR-1
            cluster-dump
                ...
        CAPTURE_DIR-2
            cluster-dump
                ...

The tool analyzes each cluster dump directory found; you need to provide only the single root directory.

To perform an analysis of the clusters:

`$ verrazzano-analysis my-cluster-dumps`

### Usage information

```
Usage: verrazzano-analysis [options] captured-data-directory
```

| Parameter | Definition | Default |
| --- | --- | --- |
| `-actions` | Include actions in the report. | `true` |
| `-help` | Display usage help. | |
| `-info` | Include informational messages. | `true` |
| `-minConfidence` | Minimum confidence threshold to report for issues, 0-10. | `0` |
| `-minImpact` | Minimum impact threshold to report for issues, 0-10. | `0` |
| `-reportFile` | Name of report output file. | Output to stdout. |
| `-support` | Include support data in the report. | `true` |
| `-version` | Display tool version. | |
