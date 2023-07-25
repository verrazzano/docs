---
title: Change Verrazzano Passwords
weight: 4
draft: false
---

### Change the Verrazzano password

To change the Verrazzano password, first change the user password in Keycloak and then update the Verrazzano secret.

**Change the user in Keycloak**

1. Navigate to the Keycloak admin console.

   a. Obtain the Keycloak admin console URL, as described [here](#get-the-consoles-urls).

   b. Obtain the Keycloak admin console credentials, as described [here](#the-keycloak-admin-console).

2. In the left pane, select the `verrazzano-system` realm from the drop-down menu.
3. In the left pane, under `Manage`, select `Users`.
4. In the `Users` pane, search for `verrazzano` or click `View all users`.
5. Select the `verrazzano` user.
6. At the top, select the `Credentials` tab.
7. Click `Reset Password`.
8. Specify the new password and confirm.
9. Specify whether the new password is a temporary password. A temporary password must be reset on next login.
10. Save and confirm the password reset by clicking `Reset password` in the confirmation dialog.

**Update the Verrazzano secret**

Get the base64 encoding for your new password.
{{< clipboard >}}
<div class="highlight">

    $ echo -n '<new password of verrazzano user>' | base64

</div>
{{< /clipboard >}}

Update the password in the secret to replace the existing password value with the new base64 encoded value.
{{< clipboard >}}
<div class="highlight">

    $ kubectl patch secret verrazzano -n verrazzano-system -p '{"data": {"password": "<base64 password of verrazzano user>"}}'

</div>
{{< /clipboard >}}

### Change the Keycloak administrator password

To change the Keycloak administrator password, first change the user password in Keycloak and then update the Keycloak secret.

**Change the administrator user in Keycloak**

1. Navigate to the Keycloak admin console.

   a. Obtain the Keycloak admin console URL, as described [here](#get-the-consoles-urls).

   b. Obtain the Keycloak admin console credentials, as described [here](#the-keycloak-admin-console).

2. In the left pane, select the `master` realm from the drop-down menu.
3. In the left pane, under `Manage`, select `Users`.
4. In the `Users` pane, select the `keycloakadmin` user.
5. At the top, select the `Credentials` tab.
6. Click `Reset password`.
7. Specify the new password and confirm.
8. Specify whether the new password is a temporary password. A temporary password must be reset on next login.
9. Save and confirm the password reset by clicking `Reset password` in the confirmation dialog.

**Update the Keycloak secret**

Get the base64 encoding for your new password.
{{< clipboard >}}
<div class="highlight">

    $ echo -n '<new password for keycloakadmin user>' | base64

</div>
{{< /clipboard >}}

Update the password in the secret to replace the existing password value with the new base64 encoded value.
{{< clipboard >}}
<div class="highlight">

    $ kubectl patch secret keycloak-http -n keycloak -p '{"data": {"password": "<base64 password of keycloakadmin user>"}}'

</div>
{{< /clipboard >}}
