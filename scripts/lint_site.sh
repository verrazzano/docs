#!/bin/bash

#
# Copyright (c) 2021, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#

set -e

FAILED=0

LANGS="en"

# This performs link checking and style checking over markdown files in a content
# directory. It transforms the shortcode sequences we use to annotate code blocks
# into classic markdown ``` code blocks, so that the linters aren't confused
# by the code blocks
check_content() {
    DIR=$1
    LANG=$2
    TMP=$(mktemp -d)

    # check for use of ```
    # if grep -nr -e "\`\`\`" --include "*.md" "${DIR}"; then
    #     echo "Ensure markdown content uses {{< text >}} for code blocks rather than \`\`\`."
    #     FAILED=1
    # fi

    # make the tmp dir
    mkdir -p "${TMP}"

    # create a throwaway copy of the content
    cp -R "${DIR}" "${TMP}"

    # replace the {{< text >}} shortcodes with ```plain
    find "${TMP}" -type f -name \*.md -exec sed -E -i "s/\\{\\{< text .*>\}\}/\`\`\`plain/g" {} ";"

    # replace the {{< /text >}} shortcodes with ```
    find "${TMP}" -type f -name \*.md -exec sed -E -i "s/\\{\\{< \/text .*>\}\}/\`\`\`/g" {} ";"

    # elide url="*"
    find "${TMP}" -type f -name \*.md -exec sed -E -i "s/url=\".*\"/URL/g" {} ";"

    # elide link="*"
    find "${TMP}" -type f -name \*.md -exec sed -E -i "s/link=\".*\"/LINK/g" {} ";"

    # switch to the temp dir
    pushd "${TMP}" >/dev/null

    if grep -nrP -e "\(https://verrazzano.io/(?!v[0-9]\.[0-9]/|archive/)" .; then
        echo "Ensure markdown content uses relative references to verrazzano.io"
        FAILED=1
    fi

    if grep -nr -e https://github.com/verrazzano/docs/blob/ .; then
        echo "Ensure markdown content uses {{< github_blob >}}"
        FAILED=1
    fi

    if grep -nr -e https://github.com/verrazzano/docs/tree/ .; then
        echo "Ensure markdown content uses {{< github_tree >}}"
        FAILED=1
    fi

    if grep -nr --exclude='*.sh' -e https://raw.githubusercontent.com/verrazzano/docs/ .; then
        echo "Ensure markdown content uses {{< github_file >}}"
        FAILED=1
    fi

    # go back whence we came
    popd >/dev/null

    # cleanup
    rm -fr "${TMP}"
}

for lang in $LANGS; do
    if [[ "$lang" == "en" ]]; then
        list=$(find ./content/en/docs -name 'index.md' -not -exec grep -q '^owner: ' {} \; -print)
        if [[ -n $list ]]; then
            echo "$list"
            echo "Ensure every document index.md file includes an owner: attribute in its metadata"
            FAILED=1
        fi

        check_content "content/$lang" --en-us

        while IFS= read -r -d '' f; do
            if grep -H -n -e '“' "${f}"; then
                # shellcheck disable=SC1111
                echo "Ensure content only uses standard quotation marks and not “"
                FAILED=1
            fi
        done < <(find ./content/en -type f \( -name '*.html' -o -name '*.md' \) -print0)
    else
        check_content "content/$lang" --en-us
    fi
done

if [[ ${FAILED} -eq 1 ]]; then
    echo "LINTING FAILED"
    exit 1
fi
