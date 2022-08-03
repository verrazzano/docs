---
title: Bug Report Tool
linkTitle: Bug Report Tool
weight: 1
description: Use the Bug Report Tool to capture and archive cluster information
draft: false
---

Use the `$ vz bug-report` command to selectively capture cluster information and create an archive (`.tar.gz`) file to help diagnose problems. The archive file will help support and development teams analyze issues and provide recommendations.

## CLI setup
To set up the `$ vz` command-line tool, follow the steps [here]({{< relref "docs/setup/cli/_index.md" >}}).

## Use the `$ vz bug-report` tool

To create a cluster snapshot in a TAR file named `my-bug-report.tar.gz`:

`$ vz bug-report --report-file my-bug-report.tar.gz`

We suggest that you review the contents of the bug report before sharing it with support and development teams.

### Usage information

Use the following syntax to run `$ vz` commands from your terminal window.
```shell
$ vz bug-report [flags]
```
### Available options

| Command                            | Definition                                                                                                                                                                                           |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-h, --help `                      | Help for `$ vz bug-report` command.                                                                                                                                                                  |
| `-i, --include-namespaces strings` | A comma-separated list of additional namespaces to collect information from the cluster. This flag can be specified multiple times, such as `--include-namespaces ns1 --include-namespaces ns...`    |
| `-r, --report-file string`         | The report file to be created by `bug-report` command, as a `.tar.gz` file. Defaults to `bug-report.tar.gz` in the current directory.                                                                |

### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |

### Examples
```
# Create a bug report bugreport.tar.gz by collecting data from the cluster
$ vz bug-report --report-file bugreport.tar.gz

When the --report-file is not provided, the command creates bug-report.tar.gz in the current directory.

# Create a bug report bugreport.tgz, including additional namespace ns1 from the cluster
$ vz bug-report --report-file bugreport.tgz --include-namespaces ns1

The flag --include-namespaces accepts comma-separated values. The flag can be specified multiple times.
For example, the following commands create a bug report by including additional namespaces ns1, ns2 and ns3
   a. $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2,ns3
   b. $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-namespaces ns3

The values specified for the flag --include-namespaces are case-sensitive.
```
