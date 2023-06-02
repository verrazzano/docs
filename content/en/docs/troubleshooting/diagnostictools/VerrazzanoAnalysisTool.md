---
title: Analyze Verrazzano Clusters
weight: 1
description: Use the Verrazzano analysis tools to analyze clusters and cluster snapshots
draft: false
---

Verrazzano provides the `vz analyze` command-line tool, which assists in troubleshooting issues in your environment. You can use it to analyze a cluster as well as, to analyze a cluster snapshot captured by the `vz bug-report` tool. For detailed information about `vz bug-report`, see [here]({{< relref "docs/troubleshooting/diagnostictools/VZBugReportCLI.md" >}}).

The `vz analyze` command-line tool analyzes the cluster or a cluster snapshot, reports the issues found, and prescribes related actions to take. Users, developers, and Continuous Integration (CI) can use this tooling to quickly identify the root cause of encountered problems, determine mitigation actions, and provide a sharable report with other users or tooling.

## Set up the CLI tool
To set up the `vz` command-line tool, follow the steps [here]({{< relref "docs/setup/install/prepare/cli-setup.md" >}}).

## Analyze clusters
To analyze a Kubernetes cluster:
{{< clipboard >}}

```shell
$ vz analyze
```
{{< /clipboard >}}

## Analyze cluster snapshots

1. Use the `vz bug-report` tool to capture a cluster snapshot.

   To create a bug report in a TAR file named `my-bug-report.tar.gz` and extract it to a directory `my-cluster-snapshot`:
{{< clipboard >}}

   ```shell
   $ vz bug-report my-bug-report.tar.gz
     mkdir my-cluster-snapshot
     tar -xvf my-bug-report.tar.gz -C my-cluster-snapshot
   ```
{{< /clipboard >}}

1. Use the `vz analyze` tool to analyze the cluster snapshot.

   To perform an analysis of the cluster snapshot under `my-cluster-snapshot`:
{{< clipboard >}}

   ```shell
   $ vz analyze --capture-dir my-cluster-snapshot
   ```
{{< /clipboard >}}

### Use the vz analyze tool to analyze multiple snapshots

The `vz analyze` tool will find and analyze all cluster snapshot directories found under a specified root directory.
This lets you create a directory to hold the cluster snapshots of related clusters in subdirectories, which the tool can then analyze.

For example:

    my-cluster-snapshots
        CAPTURE_DIR-1
            cluster-snapshot
                ...
        CAPTURE_DIR-2
            cluster-snapshot
                ...

To perform an analysis of the clusters under `my-cluster-snapshots`:
{{< clipboard >}}
```shell
$ vz analyze --capture-dir my-cluster-snapshots
```
{{< /clipboard >}}

### Usage information

Use the following syntax to run `vz` commands from your terminal window.

{{< clipboard >}}

```shell
$ vz analyze [flags]
```
{{< /clipboard >}}

#### Available options

| Command                  | Definition                                                                                              |
|--------------------------|---------------------------------------------------------------------------------------------------------|
| `--capture-dir string`   | Directory holding the captured data.                                                                    |
| `-h, --help`             | Help for the `vz analyze` command.                                                                      |
| `--report-file string`   | Name of the report output file. (Default `stdout`)                                                      |
| `--report-format string` | The format of the report output. Valid report formats are "summary" and "detailed". (Default "summary") |
| `-v, --verbose`          | Enable verbose output.                                                                                   |

#### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the kubeconfig file context to use. |
| `--kubeconfig string` | Path to the kubeconfig file to use.        |
