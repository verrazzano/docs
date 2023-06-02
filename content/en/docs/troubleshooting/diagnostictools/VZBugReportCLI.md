---
title: Use the Bug Report Tool
weight: 2
description: Use the Bug Report command-line tool to capture and archive cluster information
draft: false
---

Use the `vz bug-report` tool to selectively capture cluster information and create an archive (`*.tar.gz`) file to help diagnose problems. The archive file helps development and support teams analyze issues and provide recommendations.

## CLI setup
To set up the `vz` command-line tool, follow the steps [here]({{< relref "docs/setup/install/prepare/cli-setup.md" >}}).

## Use the vz bug-report tool

To create a bug report in a TAR file named `my-bug-report.tar.gz`:
{{< clipboard >}}

```shell
$ vz bug-report --report-file my-bug-report.tar.gz
```
{{< /clipboard >}}

We suggest that you review the contents of the bug report before sharing it with support and development teams.

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
{{< clipboard >}}

```shell
$ vz bug-report [flags]
```
{{< /clipboard >}}

### Available options

| Command                          | Definition                                                                                                                                                                                   |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-h, --help `                    | Help for the `vz bug-report` command.                                                                                                                                                            |
| `-i, --include-namespaces strings` |  A comma-separated list of namespaces, in addition to the ones collected by default (system namespaces), for collecting cluster information. This flag can be specified multiple times, such as `--include-namespaces ns1 --include-namespaces ns...` |
| `-r, --report-file string`       | The report file created by the `vz bug-report` command, as a `*.tar.gz` file. Defaults to `bug-report.tar.gz` in the current directory.                                                      |
| `-l --include-logs`              | Include logs from the pods in one or more namespaces; this is specified along with the `--include-namespaces` flag.                                                                                        |
| `-d --duration duration`         | The time period during which the logs are collected in seconds, minutes, and hours.                                                                                                          |
| `-v, --verbose`                  | Enable verbose output.                                                                                                                                                                       |

### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the kubeconfig file context to use. |
| `--kubeconfig string` | Path to the kubeconfig file to use.        |

### Examples

- Create a bug report file, `bugreport.tar.gz`, by collecting data from the cluster:
{{< clipboard >}}
   ```shell
   $ vz bug-report --report-file bugreport.tar.gz
   ```
{{< /clipboard >}}

  When `--report-file` is not provided, the command creates `bug-report.tar.gz` in the current directory.


- Create a bug report file, `bugreport.tar.gz`, including the additional namespace `ns1` from the cluster:
{{< clipboard >}}
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1
   ```
{{< /clipboard >}}

- The flag `--include-namespaces` accepts comma-separated values and can be specified multiple times.
For example, the following commands create a bug report by including the additional namespaces `ns1`, `ns2`, and `ns3`:
{{< clipboard >}}
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2,ns3
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-namespaces ns3
   ```
{{< /clipboard >}}

- Use the `--include-logs` flag to collect the logs from the pods in one or more namespaces, by specifying the `--include-namespaces` flag.
For example, the following command creates a bug report by including the logs from the additional namespaces `ns1` and `ns2`:
{{< clipboard >}}
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs
   ```
{{< /clipboard >}}
- The `--duration` flag collects logs for the specified time period. The default value is zero (`0`), which collects the complete pod log. You can specify seconds, minutes, and hours.
For example, the following commands create bug reports by including the logs from the additional namespaces `ns1` and `ns2` during the specified periods of time:
{{< clipboard >}}
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 5m
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 2h
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 300s
   ```
{{< /clipboard >}}

   The values specified for the flag `--include-namespaces` are case-sensitive.
