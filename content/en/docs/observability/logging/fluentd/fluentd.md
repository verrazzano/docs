---
title: Customize Fluentd
description: Configure the Fluentd SELinux context type
Weight: 5
draft: false
aliases:
  - /docs/customize/fluentd
---


When running Verrazzano on clusters where the nodes have SELinux `enforcing` mode enabled, there are a few considerations to keep in mind. SELinux provides an extra layer of security by enforcing mandatory access controls on processes and files.

#### Update the SELinux context type for Fluentd

By default, Fluentd is deployed with the SELinux context type `container_t`, which grants only read access to host directories (`/var/log/`). However, Fluentd may require additional permissions to function properly on SELinux `enforcing` nodes.

To grant Fluentd the required permissions, override the default SELinux context type in the Verrazzano Custom Resource and provide the SELinux type `spc_t`, which designates the Fluentd container as a super privileged container.
{{< clipboard >}}
```yaml
spec:
  components:
    fluentd:
      overrides:
      - values:
          seLinuxOptions:
            type: spc_t
```
{{< /clipboard >}}
{{< alert title="NOTE" color="primary" >}}
The `spc_t` SELinux context is very permissive because it grants the pod full access to the node on which it is running.
{{< /alert >}}

Alternatively, if you don't want the Fluentd pod to have the `spc_t` context, consider creating a custom SELinux context type with only the required privileges on all the worker nodes.

To create a custom SELinux context type, consider the following permissions required by the Fluentd container to work smoothly:
- Permission to read the log files in the directory `/var/log/containers/` on the host.
- Permission to write the `.pos` file in the directory `/var/log` on the host, using the tail plug-in.
- Permission to read the journal logs in the directory `/var/run/journal` on the host, using the systemd plug-in.
- Permission to write the `.pos` file in the directory `/tmp/`, using the systemd plug-in.

Update the custom SELinux context type in the Verrazzano Custom Resource.
{{< clipboard >}}
```yaml
spec:
  components:
    fluentd:
      overrides:
      - values:
          seLinuxOptions:
            type: <custom selinux type>
```
{{< /clipboard >}}
