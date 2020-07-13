// Copyright (c) 2020, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
if (navigator.serviceWorker) {
  navigator.serviceWorker.register(
    "{{ "/sw.js" | relURL }}", 
    { scope: "{{ "/" | relURL }}" }
  );
}
