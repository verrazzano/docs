// Copyright (c) 2020, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
'use strict';

(function() {
  const indexCfg = {{ with i18n "bookSearchConfig" }}
    {{ . }};
  {{ else }}
   {};
  {{ end }}

  indexCfg.doc = {
    id: 'id',
    field: ['title', 'content'],
    store: ['title', 'href'],
  };

  const index = FlexSearch.create('balance', indexCfg);
  window.bookSearchIndex = index;

  {{ range $index, $page := where .Site.Pages "Kind" "in" (slice "page" "section") }}
  index.add({
    'id': {{ $index }},
    'href': '{{ $page.RelPermalink }}',
    'title': {{ (partial "docs/title" $page) | jsonify }},
    'content': {{ $page.Plain | jsonify }}
  });
  {{- end -}}
})();
