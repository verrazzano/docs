---
title: CLI Setup
linkTitle:
weight: 2
description: Install the Verrazzano command-line tool (optional)
draft: false
aliases:
  - /docs/setup/cli
---

The Verrazzano command-line tool, `vz`, is available for Linux and Mac systems.
Download the binary you want from the [Releases](https://github.com/verrazzano/verrazzano/releases/) page.

{{< alert title="NOTE" color="primary" >}}
- Installing the command-line tool, `vz`, is optional.
- For optimal functionality, install or upgrade the CLI version to match the desired Verrazzano version.    
{{< /alert >}}

## Install the vz CLI

These instructions demonstrate installing the CLI on Linux AMD64 machines.

### Download the latest release
{{< clipboard >}}
<div class="highlight">

     $ curl -LO {{<release_asset_url linux-amd64.tar.gz>}}

</div>
{{< /clipboard >}}

### Validate the binary (optional)
Download the `vz` checksum file.
{{< clipboard >}}
<div class="highlight">

     $ curl -LO {{<release_asset_url linux-amd64.tar.gz.sha256>}}

</div>
{{< /clipboard >}}

Validate the `vz` binary against the checksum file.
{{< clipboard >}}
<div class="highlight">

    $ sha256sum -c verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz.sha256

</div>
{{< /clipboard >}}

### Unpack and copy the vz binary

  ```shell
   $ tar xvf verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz
  ```
  The following command needs to be run as root.
  ```shell
   $ sudo cp verrazzano-{{<verrazzano_development_version>}}/bin/vz /usr/local/bin
  ```

### Test to ensure that the version you installed is up-to-date
{{< clipboard >}}
<div class="highlight">

     $ vz version

</div>
{{< /clipboard >}}

The resulting output should be similar to the following.
{{< clipboard >}}
<div class="highlight">

    Version: {{<release_version>}}
    BuildDate: 2023-02-12T21:07:26Z
    GitCommit: cb0778bbf7a2cd90e1ae8458abd242f9da27a100

</div>
{{< /clipboard >}}

## Use the vz CLI

Verrazzano provides a command-line tool for managing a Verrazzano environment using the Verrazzano and Kubernetes API.

Common use cases include installing, upgrading, and uninstalling Verrazzano,
as well as analyzing failures in a running Verrazzano environment.

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
{{< clipboard >}}
<div class="highlight">

    vz [command] [flags]

</div>
{{< /clipboard >}}

### Available commands

| Command      | Definition                                                      |
|--------------|-----------------------------------------------------------------|
| `analyze`    | Analyze cluster                                                 |
| `bug-report` | Collect information from the cluster to report an issue         |
| `completion` | Generate the autocompletion script for the specified shell      |
| `help`       | Help about any command                                          |
| `install`    | Install Verrazzano                                              |
| `status`     | Status of the Verrazzano installation and access endpoints      |
| `uninstall`  | Uninstall Verrazzano                                            |
| `upgrade`    | Upgrade Verrazzano                                              |
| `version`    | Verrazzano version information                                  |

### Available Flags

These flags apply to all the commands.

| Flag                  | Definition                                      |
|-----------------------|-------------------------------------------------|
| `--context string`    | The name of the kubeconfig file context to use. |
| `-h`, `--help`        | Help for `vz`.                                  |
| `--kubeconfig string` | Path to the kubeconfig file to use.             |
