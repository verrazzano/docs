---
title: Bug Reports
linkTitle: Bug Reports
weight: 2
description: Use the Bug Report command-line tool to capture and archive cluster information
draft: false
---

Use the `vz bug-report` tool to selectively capture cluster information and create an archive (`*.tar.gz`) file to help diagnose problems. The archive file helps development and support teams analyze issues and provide recommendations.

## CLI setup
To set up the `vz` command-line tool, follow the steps [here]({{< relref "docs/setup/cli/_index.md" >}}).

## Use the `vz bug-report` tool

To create a bug report in a TAR file named `my-bug-report.tar.gz`:
```shell
$ vz bug-report --report-file my-bug-report.tar.gz
```

We suggest that you review the contents of the bug report before sharing it with support and development teams.

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
```shell
$ vz bug-report [flags]
```
### Available options

| Command                          | Definition                                                                                                                                                                                   |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-h, --help `                    | Help for `vz bug-report` command.                                                                                                                                                            |
| `-i, --include-namespaces strings` | A comma-separated list of additional namespaces for collecting cluster information. This flag can be specified multiple times, such as `--include-namespaces ns1 --include-namespaces ns...` |
| `-r, --report-file string`       | The report file created by the `vz bug-report` command, as a `*.tar.gz` file. Defaults to `bug-report.tar.gz` in the current directory.                                                      |
| `-l --include-logs`              | Include logs from the pods in one or more namespaces; this is specified using `--include-namespaces`.                                                                                        |
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
   ```shell
   $ vz bug-report --report-file bugreport.tar.gz
   ```

  When `--report-file` is not provided, the command creates `bug-report.tar.gz` in the current directory.


- Create a bug report file, `bugreport.tar.gz`, including the additional namespace `ns1` from the cluster:
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1
   ```

- The flag `--include-namespaces` accepts comma-separated values and can be specified multiple times.
For example, the following commands create a bug report by including additional namespaces `ns1`, `ns2`, and `ns3`:
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2,ns3
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-namespaces ns3
   ```
- Use the `--include-logs` flag to collect the logs from the pods in one or more namespace, specified using `--include-namespaces`.
For example, the following command creates a bug report by including additional namespaces `ns1` and `ns2` logs:
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs
   ```
- The flag `--duration` collects logs for a specific period. The default value is 0, which collects the complete pod log. It supports seconds, minutes, and hours.
For example, the following commands creates a bug report by including additional namespaces `ns1` and `ns2` logs with specific time duration:
   ```shell
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 5m
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 2h
   $ vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-logs --duration 300s
   ```

   The values specified for the flag `--include-namespaces` are case-sensitive.
