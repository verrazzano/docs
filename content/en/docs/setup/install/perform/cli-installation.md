---
title: "Install With CLI"
description: "Install Verrazzano using the `vz` CLI"
weight: 1
draft: false
aliases:
- /docs/setup/install/installation
- /docs/setup/install/cli-installation
---

The following instructions show you how to install Verrazzano in a
single Kubernetes cluster using the CLI.

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/install/prepare/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/install/prepare/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/install/prepare/prereqs.md#installed-components" >}}) by Verrazzano.

{{< alert title="NOTE" color="primary" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Prepare for the installation

Before installing Verrazzano, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/install/prepare/platforms/" >}}) and installing the [Verrazzano CLI]({{< relref "docs/setup/install/prepare/cli-setup.md" >}}) (optional).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing Verrazzano.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

## Perform the installation

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/vpo-verrazzano-v1beta1" >}})
custom resource, you can install, uninstall, and upgrade Verrazzano installations. When applying the Verrazzano custom resource, the Verrazzano CLI deploys and installs the Verrazzano platform operator; you need only to install Verrazzano as described in the following section.

Verrazzano supports the following installation profiles:  development (`dev`), production (`prod`), and
managed cluster (`managed-cluster`).  For more information, see
[Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md"  >}}).

This document shows how to create a basic Verrazzano installation using:

* The development (`dev`) installation profile
* Wildcard-DNS, where DNS is provided by [nip.io](https://nip.io) (the default)

**NOTE**: Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/troubleshooting/faq.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).

For an overview of how to configure Verrazzano, see [Modify Verrazzano Installations]({{< relref "/docs/setup/modify-installation.md" >}}).
For a complete description of Verrazzano configuration options, see the
[Verrazzano Custom Resource Definition]({{< relref "/docs/reference/vpo-verrazzano-v1beta1" >}}).

To use other DNS options, see [Customizing DNS]({{< relref "/docs/customize/dns" >}}) for more details.

#### Install Verrazzano

To create a Verrazzano installation as described in the previous section, run the following commands.

1. Install Verrazzano with its `dev` profile.
{{< clipboard >}}
```bash
    $ vz install -f - <<EOF
    apiVersion: install.verrazzano.io/v1beta1
    kind: Verrazzano
    metadata:
      name: example-verrazzano
    spec:
      profile: dev
      defaultVolumeSource:
        persistentVolumeClaim:
          claimName: verrazzano-storage
      volumeClaimSpecTemplates:
        - metadata:
            name: verrazzano-storage
          spec:
            resources:
              requests:
                storage: 2Gi
    EOF
```
{{< /clipboard >}}

This command installs the Verrazzano platform operator and applies the Verrazzano custom resource.

2. Wait for the installation to complete.
   Installation logs will be streamed to the command window until the installation has completed
   or until the default timeout (30m) has been reached.

To use a different profile with the previous example, set the `VZ_PROFILE` environment variable to the name of the profile you want to install.

## Next steps

Verify the installed Verrazzano using the `vz` CLI. See [Verify using CLI]({{< relref "/docs/setup/install/verify/cli-verify.md" >}}).
