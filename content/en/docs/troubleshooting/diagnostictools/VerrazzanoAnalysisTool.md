---
title: Verrazzano Analysis Tools
linkTitle: Verrazzano Analysis Tools
weight: 1
description: Use the Verrazzano analysis tools to analyze cluster snapshots
draft: false
---


Verrazzano provides tooling which assists in troubleshooting issues in your environment:
1. `k8s-dump-cluster.sh` - a shell script tool
2. `vz analyze` - a command-line tool

## Download the shell script tool

{{< tabs tabTotal="2" >}}
{{< tab tabName="Linux" >}}
<br>


Use these instructions to obtain the shell script tool on Linux machines.

#### Download the tooling
  ```
   $ wget {{<release_asset_url k8s-dump-cluster.sh>}}
   $ wget {{<release_asset_url k8s-dump-cluster.sh.sha256>}}
  ```

#### Verify the downloaded files
  ```
   $ sha256sum -c k8s-dump-cluster.sh.sha256
  ```

{{< /tab >}}
{{< tab tabName="macOS" >}}
<br>


Use these instructions to obtain the shell script tool on Mac machines.

#### Download the tooling
  ```
   $ wget {{<release_asset_url k8s-dump-cluster.sh>}}
   $ wget {{<release_asset_url k8s-dump-cluster.sh.sha256>}}
  ```
#### Verify the downloaded files
  ```
   $ shasum -a 256 -c k8s-dump-cluster.sh.sha256
  ```

{{< /tab >}}
{{< /tabs >}}

## Set up the CLI tool
To set up the `vz` command-line tool, follow the steps [here]({{< relref "docs/setup/cli/_index.md" >}}).

## First, use the `k8s-dump-cluster.sh` tool

The `k8s-dump-cluster.sh` tool is a shell script which runs various `kubectl` and `helm` commands against a cluster.

The directory structure created by the `k8s-dump-cluster.sh` tool, for a specific cluster snapshot, appears as follows:

    $ CAPTURE_DIR
      cluster-snapshot
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

Note that the data captured by this script might include sensitive information; you can choose whether to share it.

The script shows the `kubectl` and `helm` commands which are run. The basic structure, shown previously, is formed by running the command, `$ kubectl cluster-info dump --all-namespaces`, with additional data captured into that directory structure.

To create a cluster snapshot in a directory named `my-cluster-snapshot`:
```shell
$ sh k8s-dump-cluster.sh -d my-cluster-snapshot
```

## Then, use the `vz analyze` tool

The `vz analyze` command-line tool analyzes data from a cluster snapshot captured using the shell script tool, reports the issues found, and prescribes related actions to take. Users,
developers, and Continuous Integration (CI) can use this tooling to quickly identify the root cause of encountered problems, determine mitigation actions, and provide a sharable report with other users or tooling.

The data that the analysis examines follows the structure created by the corresponding capture tooling. For example, `k8s-dump-cluster.sh` takes a snapshot of a cluster and places it into a specific structure. The tooling analyzes the data and provides you with a report, which identifies issues and provides you with actions to take.

The `vz analyze` tool will find and analyze all cluster snapshot directories found under a specified root directory. This lets you create a directory to hold the cluster snapshots of related clusters in sub-directories, which the tool can analyze.

For example:

    my-cluster-snapshots
        CAPTURE_DIR-1
            cluster-snapshot
                ...
        CAPTURE_DIR-2
            cluster-snapshot
                ...

The tool analyzes each cluster snapshot directory found; you need to provide only the single root directory.

To perform an analysis of the clusters:
```shell
$ vz analyze --capture-dir my-cluster-snapshots
```

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
```shell
$ vz analyze [flags]
```

#### Available options

| Command                  | Definition                                                                           |
|--------------------------|--------------------------------------------------------------------------------------|
| `--capture-dir string`   | Directory holding the captured data. (Required)                                      |
| `-h, --help`             | Help for the `vz analyze` command.                                                   |
| `--report-file string`   | Name of the report output file. (Default `stdout`)                                       |
| `--report-format string` | The format of the report. Valid output format is "simple". (Default "simple") |

#### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |
