---
title: Verrazzano Analysis Tools
linkTitle: Verrazzano Analysis Tools
weight: 1
description: Use the Verrazzano analysis tools to analyze live cluster and cluster snapshots
draft: false
---


Verrazzano provides `vz analyze` command-line tool which assists in troubleshooting issues in your environment. It can be used to analyze a live cluster as well as to analyze a cluster snapshot captured by `vz bug-report` tool. More details about `vz bug-report` available [here]({{< relref "docs/troubleshooting/diagnostictools/VZBugReportCLI.md" >}}).

The `vz analyze` command-line tool analyzes the cluster or a cluster snapshot, reports the issues found, and prescribes related actions to take. Users, developers, and Continuous Integration (CI) can use this tooling to quickly identify the root cause of encountered problems, determine mitigation actions, and provide a sharable report with other users or tooling.

## Set up the CLI tool
To set up the `vz` command-line tool, follow the steps [here]({{< relref "docs/setup/cli/_index.md" >}}).

## Analyze live  cluster
To analyze a live Kubernetes cluster:
```shell
$ vz analyze
```

## Analyze cluster snapshot

### Use the `vz bug-report` tool to capture the cluster snapshot

To create a bug report in a TAR file named `my-bug-report.tar.gz` and extract to a directory `my-cluster-snapshot`:
```shell
$ vz bug-report my-bug-report.tar.gz
  mkdir my-cluster-snapshot
  tar -xvf my-bug-report.tar.gz -C my-cluster-snapshot
```

### Use the `vz analyze` tool

To perform an analysis of the clusters under my-cluster-snapshot:
```shell
$ vz analyze --capture-dir my-cluster-snapshot
```

The `vz analyze` tool will find and analyze all cluster snapshot directories found under a specified root directory. This lets you create a directory to hold the cluster snapshots of related clusters in sub-directories, which the tool can analyze.

For example:

    my-cluster-snapshots
        CAPTURE_DIR-1
            cluster-snapshot
                ...
        CAPTURE_DIR-2
            cluster-snapshot
                ...

To perform an analysis of the clusters under my-cluster-snapshots:
```shell
$ vz analyze --capture-dir my-cluster-snapshots
```

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
```shell
$ vz analyze [flags]
```

#### Available options

| Command                  | Definition                                                                                              |
|--------------------------|---------------------------------------------------------------------------------------------------------|
| `--capture-dir string`   | Directory holding the captured data.                                                                    |
| `-h, --help`             | Help for the `vz analyze` command.                                                                      |
| `--report-file string`   | Name of the report output file. (Default `stdout`)                                                      |
| `--report-format string` | The format of the report output. Valid report formats are "summary" and "detailed". (default "summary") |
| `-v, --verbose`          | Enable verbose output                                                                                   |

#### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |
