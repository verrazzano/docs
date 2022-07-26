---
title: Verrazzano Bug Report Tools
linkTitle: Verrazzano Bug Report Tools
weight: 1
description: Use the Verrazzano Bug Report Tools to selectively capture the information from cluster and create an archive of it
draft: false
---


The Verrazzano command `vz bug-report` aims to selectively capture the information from the cluster and create an archive `(.tar.gz)` to help diagnose problems. The archive should be sufficient for the support / development teams to analyze the issue and provide a recommendation.

## CLI Setup
Follow the steps here to setup vz cli: https://verrazzano.io/latest/docs/setup/cli/

## Use the `vz bug-report` tool

The `vz bug-report` is a CLI tool which runs various `kubectl` and `helm` commands against a cluster.
Note that the data captured by this tool might include sensitive information. This data is under your control; you can choose whether to share it.

The directory structure created by the `vz bug-report` tool, for a specific cluster snapshot, appears as follows:

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

### Available Options

| Command                            | Definition                                                                                                                                                                                    |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-h, --help `                      | help for bug-report                                                                                                                                                                           |
| `-i, --include-namespaces strings` | A comma separated list of additional namespaces to collect information from the cluster. This flag can be specified multiple times like `--include-namespaces ns1 --include-namespaces ns...` |
| `-r, --report-file string`         | The report file to be created by bug-report command, as a `.tar.gz` file. Defaults to `bug-report.tar.gz` in the current directory.                                                             |

### Available Flags

These flags apply to all the commands.

| Flag                  | Definition                                   |
|-----------------------|----------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |
