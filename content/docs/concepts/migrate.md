---
title: "Migrate WLS domains to Verrazzano"
weight: 4
---

Use WebLogic Server Deploy Tooling to move WLS domains to Verrazzano.

You can use the Discover Domain Tool and the Prepare Model Tool
to create Verrazzano model and binding YAML files.

The Discover Domain Tool introspects an existing domain and creates a model file describing the domain and an archive file of the binaries deployed to the domain.
For detailed usage instructions, see the [Discover Domain Tool](https://github.com/oracle/weblogic-deploy-tooling/blob/master/site/discover.md).

The Prepare Model Tool prepares model files for deploying to specific target environments. For detailed usage instructions, see the
[Prepare Model Tool](https://github.com/oracle/weblogic-deploy-tooling/blob/master/site/prepare.md). For information on how target an Verrazzano environment,
see [The Verrazzano Target](https://github.com/oracle/weblogic-deploy-tooling/blob/master/site/config/target_env.md#the-verrazzano-target).
