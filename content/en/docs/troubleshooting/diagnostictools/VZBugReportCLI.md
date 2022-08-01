---
title: Verrazzano Bug Report Tool
linkTitle: Verrazzano Bug Report Tool
weight: 1
description: Use the Verrazzano Bug Report Tool to selectively capture the information from cluster and create an archive of it
draft: false
---


The Verrazzano command `vz bug-report` aims to selectively capture the information from the cluster and create an archive `(.tar.gz)` to help diagnose problems. The archive should be sufficient for the support / development teams to analyze the issue and provide a recommendation.

## CLI Setup
Follow the steps here to setup vz cli: https://verrazzano.io/latest/docs/setup/cli/

## Use the `vz bug-report` tool

The `vz bug-report` is a CLI tool captures cluster data based on provided kubeconfig and context. 
Note that the data captured by this tool might include sensitive information. Please examine the contents of the bug report for any sensitive data before sharing with Verrazzano support / development teams.

To perform a snapshot of a cluster into a tar file named `my-bug-report.tar.gz`:

`$ vz bug-report --report-file my-bug-report.tar.gz`

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
```shell
vz bug-report [flags]
```
### Examples
```
# Create a bug report bugreport.tar.gz by collecting data from the cluster
vz bug-report --report-file bugreport.tar.gz

When the --report-file is not provided, the command attempts to create bug-report.tar.gz in the current directory.

# Create a bug report bugreport.tgz, including additional namespace ns1 from the cluster
vz bug-report --report-file bugreport.tgz --include-namespaces ns1

The flag --include-namespaces accepts comma separated values. The flag can also be specified multiple times.
For example, the following commands create a bug report by including additional namespaces ns1, ns2 and ns3
   a. vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2,ns3
   b. vz bug-report --report-file bugreport.tgz --include-namespaces ns1,ns2 --include-namespaces ns3

The values specified for the flag --include-namespaces are case-sensitive.
```

### Available options

| Command                            | Definition                                                                                                                                                                                    |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-h, --help `                      | help for bug-report                                                                                                                                                                           |
| `-i, --include-namespaces strings` | A comma-separated list of additional namespaces to collect information from the cluster. This flag can be specified multiple times, such as `--include-namespaces ns1 --include-namespaces ns...` |
| `-r, --report-file string`         | The report file to be created by `bug-report` command, as a `.tar.gz` file. Defaults to `bug-report.tar.gz` in the current directory.                                                           |

### Available flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |
