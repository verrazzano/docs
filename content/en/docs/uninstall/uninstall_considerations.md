---
title: "Uninstall Considerations"
linkTitle: "Uninstall Considerations"
description: "List of items that you need to consider before uninstalling Verrazzano"
weight: 1
draft: false
---

Before uninstalling Verrazzano, you should delete your Verrazzano applications because they may not function properly after the uninstall is done.

When you uninstall Verrazzano:
* All of the Verrazzano components are uninstalled
* The CRDs installed by Verrazzano are not deleted
* Any applications that were deployed will still exist, but they may not be functional
