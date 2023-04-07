This tool helps identify documentation pages from earlier releases that do not exists in a later release.
It takes into account aliases in Hugo headers.

```shell
$ go run tools/alias_linter/main.go -priorBranches release-1.0,release-1.1,release-1.2,release-1.3,release-1.4 -checkBranch release-1.5

# or between previous release branches and master
go run tools/alias_linter/main.go -priorBranches release-1.0,release-1.1,release-1.2,release-1.3,release-1.4,release-1.5 -checkBranch master

# or between two specific release branches
go run tools/alias_linter/main.go -priorBranches release-1.4 -checkBranch release-1.5
```

This will output a list of the pages of the prior branches that are missing in the check branch.
If there are no missing pages the tool will exit with a 0 exit code.
Otherwise the tool will exit with a 1 exit code.

By default the tool does an in memory clone of the https://github.com/verrazzano/docs.git repository.
This can be time consuming an may eventually be too large.
In this case the repo can be cloned before the tool is run and the -repoDir flag used to provide the location of the cloned repository.
Beware that this tool checks out all of the branches provided via -priorBranches and -checkBranch flags.
Therefore it is usually best to use a separate repository clone from the one where the tool is being run.

This example shows a safe way to clone and reference a separate copy of the docs repo. 
```shell
$ git clone https://github.com/verrazzano/docs.git /tmp/verrazzano/docs
$ go run tools/alias_linter/main.go -priorBranches release-1.0,release-1.1,release-1.2,release-1.3,release-1.4 -checkBranch release-1.5 -repoDir /tmp/verrazzano/docs
```