---
title: FAQ
weight: 6
draft: false
aliases:
  - /docs/faq
---


#### Enable Google Chrome to accept self-signed Verrazzano certificates

There are some installation scenarios where Verrazzano generates SSL certificates that are not trusted by browsers:

* The development (`dev`) profile installation, which uses its own self-signed CA to issue certificates.
* Using the [Let's Encrypt Staging](https://letsencrypt.org/docs/staging-environment) authority, which uses untrusted CAs to sign certificates.

These are typical development or testing scenarios, not recommended for production.  When accessing Verrazzano sites
using these certificates, some browsers like [Firefox](https://www.mozilla.org/en-US/firefox/new/) let you manually
accept these certificates.  However, [Google Chrome](https://www.google.com/chrome) now prevents users from being able to accept
self-signed certificates by default. This will prevent you from accessing Verrazzano consoles that are using untrusted
certificates.

When this occurs, while trying to access Verrazzano services, you will see an error message like the following:

```
opensearch.vmi.system.default.129.153.98.156.nip.io normally uses encryption to protect your information. When Chrome tried to connect to opensearch.vmi.system.default.129.153.98.156.nip.io this time, the website sent back unusual and incorrect credentials
```

You can choose to import the certificate into your local trust chain, but this will have to be done for each Verrazzano
instance. From a security perspective, this is not recommended.

As an alternative, you can enter a secret passphrase in Chrome to enable it to prompt you to accept these certificates, by doing the following:

* When you see an error such as the one shown previously, when the browser window has the keyboard focus, enter the phrase `thisisunsafe`.
* Reload the site.
* Chrome will prompt you to accept the certificate.

**NOTE**: This should be used only when accessing sites that are known to be safe, such as in this situation.

#### Related articles

- https://stackoverflow.com/questions/35274659/when-you-use-badidea-or-thisisunsafe-to-bypass-a-chrome-certificate-hsts-err

- https://miguelpiedrafita.com/chrome-thisisunsafe
