---
title: CLI Setup
linkTitle:
weight: 2
description: Install the Verrazzano command-line tool
draft: false
---

The Verrazzano command-line tool, `vz`, is available for Linux and Mac systems.
Download the binary you want from the [Releases](https://github.com/verrazzano/verrazzano/releases/) page.

## Install the `vz` CLI

These instructions demonstrate installing the CLI on Linux AMD64 machines.

### Download the latest release
  ```shell
   $ curl -LO {{<release_asset_url linux-amd64.tar.gz>}}
  ```

### Validate the binary (optional)
Download the checksum file.
  ```shell
   $ curl -LO {{<release_asset_url linux-amd64.tar.gz.sha256>}}
  ```
Validate the binary against the checksum file.
  ```shell
   $ sha256sum -c {{<release_asset -linux-amd64.tar.gz.sha256>}}
  ```

### Unpack and copy the `vz` binary
  ```shell
   $ tar xvf {{<release_asset -linux-amd64.tar.gz>}}
   $ cp {{<release_asset "/bin/vz">}} /usr/local/bin
  ```

### Test to ensure that the version you installed is up-to-date
  ```shell
   $ vz version
  ```

The resulting output should be similar to the following.

```shell
Version: v1.4.0
BuildDate: 2022-09-23T21:32:57Z
GitCommit: a34d6473a4296b8cfe64ad7851d1dcd0f18e9669
```

## Use the `vz` CLI

Verrazzano provides a command-line tool for managing a Verrazzano environment using the Verrazzano and Kubernetes API.

Common use cases include installing, upgrading, and uninstalling Verrazzano,
as well as analyzing failures in a running Verrazzano environment.

### Usage information

Use the following syntax to run `vz` commands from your terminal window.
```shell
vz [command] [flags]
```

### Available commands

| Command     | Definition                                                 |
|-------------|------------------------------------------------------------|
| `analyze`   | Analyze cluster                                            |
| `bug-report`| Collect information from the cluster to report an issue    |
| `help`      | Help about any command                                     |
| `install`   | Install Verrazzano                                         |
| `status`    | Status of the Verrazzano installation and access endpoints |
| `uninstall` | Uninstall Verrazzano                                       |
| `upgrade`   | Upgrade Verrazzano                                         |
| `version`   | Verrazzano version information                             |

### Available Flags

These flags apply to all the commands.

| Flag                  | Definition                                 |
|-----------------------|--------------------------------------------|
| `--context string`    | The name of the `kubeconfig` context to use. |
| `-h`, `--help`        | Help for `vz`.                             |
| `--kubeconfig string` | Path to the `kubeconfig` file to use.        |
