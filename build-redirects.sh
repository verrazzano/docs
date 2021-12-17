#!/bin/bash

LATEST="latest"
INDEX_FILE="_index"
DOMAIN="$1"

set -eu

function redirect_file() {
  local newPath="$1"
  local url="$DOMAIN/$LATEST/$newPath"

  echo "creating redirect for $newPath"

  mkdir -p "../../$newPath"

  echo "<!DOCTYPE html>
<html>
  <head>
    <title>$url</title>
    <link rel='canonical' href='$url'/>
    <meta name='robots' content='noindex'>
    <meta http-equiv='content-type' content='text/html; charset=utf-8'/>
    <meta http-equiv='refresh' content='0; url=$url'/>
  </head>
</html>" > "../../$newPath/index.html"
}

rm -rf docs
cd content/en

mdFiles=$(find docs -name "*.md")
for file in $mdFiles; do
  name=$(basename "$file" .md)
  path=$(dirname "$file" | awk '{print tolower($0)}')

  if [[ "$name" == "$INDEX_FILE" ]]; then
    redirect_file "$path"
  else
    name="$(echo "$name"| awk '{print tolower($0)}')"
    redirect_file "$path/$name"
  fi
done

cd -
