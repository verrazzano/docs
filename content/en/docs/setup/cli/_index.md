---
title: CLI Setup
linkTitle:
weight: 3
description: Install the Verrazzano command-line tool
draft: false
---

The Verrazzano command-line tool, `vz`, is available for Linux (AMD64/ARM64) and Mac (AMD64/ARM64) systems: https://github.com/verrazzano/verrazzano/releases/.

{{< tabs tabTotal="2" >}}
{{< tab tabName="Linux" >}}
<br>


Use these instructions to install the Verrazzano CLI on Linux AMD64 machines.

#### Download the latest release
  ```shell
   $ wget {{<release_asset_url vz-linux-amd64.tar.gz>}}
  ```

#### Validate the binary (optional)
Download the `vz` checksum file:
  ```shell
   $ wget {{<release_asset_url vz-linux-amd64.tar.gz.sha256>}}
  ```
Validate the `vz` binary against the checksum file:
  ```shell
   $ sha256sum -c vz-linux-amd64.tar.gz.sha256
  ```

#### Unpack the `vz` binary
  ```shell
   $ tar xvf vz-linux-amd64.tar.gz /usr/local/bin/vz
  ```

#### Test to ensure that the version you installed is up-to-date
  ```shell
   $ vz version
  ```
{{< /tab >}}
{{< tab tabName="macOS" >}}
<br>


Use these instructions to install the Verrazzano CLI on Mac ARM64 machines.

#### Download the latest release
  ```shell
   $ wget {{<release_asset_url vz-darwin-amd64.tar.gz>}}
  ```

#### Validate the binary (optional)
Download the `vz` checksum file:
  ```shell
   $ wget {{<release_asset_url vz-darwin-amd64.tar.gz.sha256>}}
  ```
Validate the `vz` binary against the checksum file:
  ```shell
   $ sha256sum -c vz-darwin-amd64.tar.gz.sha256
  ```

#### Unpack the `vz` binary
  ```shell
   $ tar xvf vz-darwin-amd64.tar.gz /usr/local/bin/vz
  ```

#### Test to ensure that the version you installed is up-to-date
  ```shell
   $ vz version
  ```
{{< /tab >}}
{{< /tabs >}}

## Use the `vz` CLI

Verrazzano provides a command-line tool for managing a Verrazzano environment, using the Verrazzano and Kubernetes API.

Common use cases include installing, upgrading, and uninstalling Verrazzano,
as well as analyzing failures in a running Verrazzano environment.

### Usage information

Use the following syntax to run `vz` commands from your terminal window:
```shell
vz [command] [flags]
```

Available commands:

| Command   | Definition                                                 |
|-----------|------------------------------------------------------------|
| analyze   | Analyze cluster                                            |
| help      | Help about any command                                     |
| install   | Install Verrazzano                                         |
| status    | Status of the Verrazzano installation and access endpoints |
| uninstall | Uninstall Verrazzano                                       |
| upgrade   | Upgrade Verrazzano                                         |
| version   | Verrazzano version information                             |

Available Flags:

| Flag                | Definition                                |
|---------------------|-------------------------------------------|
| --context string    | The name of the kubeconfig context to use |
| -h, --help          | Help for vz                               |
| --kubeconfig string | Path to the kubeconfig file to use        |
