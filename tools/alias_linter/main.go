package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	yaml "gopkg.in/yaml.v3"
)

type argsType struct {
	repoURL          string
	repoDir          string
	subdir           string
	checkBranch      string
	priorBranchesStr string
	priorBranches    []string
	progress         bool
	debug            bool
}

var globalArgs argsType
var markdown_re = regexp.MustCompile(`^(.*/\S*).md$`)

func main() {
	globalArgs = parseArgs()

	// Open the repo
	repo, err := openRepo(&globalArgs)
	logAndExitIfError(err)

	// Accumulate all of the pages in the prior branches
	priorPageInfo := make(map[string]map[string]struct{})
	for _, priorBranch := range globalArgs.priorBranches {
		err = accumulatePageInfoForBranch(repo, priorBranch, globalArgs.subdir, priorPageInfo)
		logAndExitIfError(err)
	}

	// Accumulate all of the pages in the check branch
	checkPageInfo := make(map[string]map[string]struct{})
	err = accumulatePageInfoForBranch(repo, globalArgs.checkBranch, globalArgs.subdir, checkPageInfo)
	logAndExitIfError(err)

	// Remove pages in the prior branches also found in the check branch
	for file, _ := range checkPageInfo {
		_, found := priorPageInfo[file]
		if found {
			delete(priorPageInfo, file)
		}
	}

	// Collect the page names for sorting
	names := make([]string, 0, len(priorPageInfo))
	for name := range priorPageInfo {
		names = append(names, name)
	}
	// Sort the page names
	sort.Strings(names)
	// Print out any remaining pages
	for _, name := range names {
		fmt.Printf("%s (%s)\n", name, joinMapKeysToString(priorPageInfo[name], ","))
	}

	// Exit with failure if any missing pages are found
	if len(priorPageInfo) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// Parse the command line arguments
func parseArgs() argsType {
	var args argsType
	flag.StringVar(&args.repoURL, "repoURL", "https://github.com/verrazzano/docs.git", "Repository URL to clone into memory")
	flag.StringVar(&args.repoDir, "repoDir", "", "Existing repository directory to open")
	flag.StringVar(&args.subdir, "subdir", "content/en", "Subdirectory")
	flag.StringVar(&args.checkBranch, "checkBranch", "master", "Name of branch to check for required pages")
	flag.StringVar(&args.priorBranchesStr, "priorBranches", "release-1.0,release-1.1,release-1.2,release-1.3,release-1.4,release-1.5", "Names of prior branches for pages to require as a commas separated list")
	flag.BoolVar(&args.progress, "progress", false, "Output repository clone progress")
	flag.BoolVar(&args.debug, "debug", false, "Output debug information")
	flag.Parse()
	args.priorBranches = strings.Split(args.priorBranchesStr, ",")
	if args.debug {
		fmt.Printf("repoURL=%s\n", args.repoURL)
		fmt.Printf("repoDir=%s\n", args.repoDir)
		fmt.Printf("subdir=%s\n", args.subdir)
		fmt.Printf("checkBranch=%s\n", args.checkBranch)
		fmt.Printf("priorBranches=%s\n", args.priorBranches)
	}
	return args
}

// Opens the repo using either repoUrl or repoDir
func openRepo(args *argsType) (*git.Repository, error) {
	if len(args.repoDir) == 0 && len(args.repoURL) == 0 {
		return nil, fmt.Errorf("must provide either repoURL or repoDir")
	}
	if len(args.repoDir) > 0 {
		return openRepoOnDisk(args.repoDir)
	}
	if len(args.repoURL) > 0 {
		return cloneRepoInMemory(args.repoURL)
	}
	// Logically unreachable
	return nil, fmt.Errorf("invalid repoURL and repoDir combination")
}

// Joins all map keys into a delimited string
func joinMapKeysToString(m map[string]struct{}, s string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, s)
}

// If err is non-nill then print the error and exit.
func logAndExitIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Clone the git repo into memory
func cloneRepoInMemory(repoURL string) (*git.Repository, error) {
	options := git.CloneOptions{
		URL: repoURL,
	}
	if globalArgs.progress {
		options.Progress = os.Stdout
	}
	r, err := git.Clone(memory.NewStorage(), nil, &options)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Open a git repo from disk
func openRepoOnDisk(repoDir string) (*git.Repository, error) {
	r, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Updates page info for a given file and branch
func addOrUpdatePageInfoForFile(fileName string, branchName string, fileInfo map[string]map[string]struct{}) {
	pageName := convertFileNameToPageName(fileName)
	info, found := fileInfo[pageName]
	if found {
		info[branchName] = struct{}{}
	} else {
		s := make(map[string]struct{})
		s[branchName] = struct{}{}
		fileInfo[pageName] = s
	}
}

// Converts a file name to a page name
func convertFileNameToPageName(fileName string) string {
	// Remove .md extension.
	fileName = strings.TrimSuffix(fileName, ".md")
	// Remove _index suffix if present.
	fileName = strings.TrimSuffix(fileName, "_index")
	// Remove leading slash if there is more than on character left.
	if len(fileName) > 1 {
		fileName = strings.TrimPrefix(fileName, "/")
	}
	// Remove trailing slash if there is more than on character left.
	if len(fileName) > 1 {
		fileName = strings.TrimSuffix(fileName, "/")
	}
	// Convert to lower case.
	return strings.ToLower(fileName)
}

// Accumulates all of the pages in the branch
func accumulatePageInfoForBranch(repo *git.Repository, branchName string, subDirName string, fileInfo map[string]map[string]struct{}) error {
	rev, err := repo.ResolveRevision(plumbing.Revision(fmt.Sprintf("origin/%s", branchName)))
	if err != nil {
		return err
	}
	commit, err := repo.CommitObject(*rev)
	if err != nil {
		return err
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}
	tree, err = tree.Tree(subDirName)
	if err != nil {
		return err
	}

	tree.Files().ForEach(func(f *object.File) error {
		if markdown_re.MatchString(f.Name) {
			addOrUpdatePageInfoForFile(f.Name, branchName, fileInfo)
			err := accumulateFileInfoForAliases(branchName, f, fileInfo)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// Accumulates page info for all of the aliases in a file
func accumulateFileInfoForAliases(branchName string, f *object.File, fileInfo map[string]map[string]struct{}) error {
	h, err := extractHeaderFromFile(f)
	if err != nil {
		return err
	}
	aliases, err := extractAliasesFromHeader(h)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		addOrUpdatePageInfoForFile(alias, branchName, fileInfo)
	}
	return nil
}

// Extracts the Hugo header string from a file
func extractHeaderFromFile(f *object.File) (string, error) {
	r, e := f.Reader()
	if e != nil {
		return "", e
	}
	defer r.Close()
	return extractHeaderFromReader(bufio.NewReader(r)), nil
}

// Extracts the Hugo header string from a reader
func extractHeaderFromReader(r *bufio.Reader) string {
	s := bufio.NewScanner(r)
	h := ""
	if !s.Scan() {
		return h
	}
	t := s.Text()
	if strings.TrimSpace(t) != "---" {
		return h
	}
	for s.Scan() {
		t = s.Text()
		if strings.TrimSpace(t) == "---" {
			break
		}
		h += t + "\n"
	}
	return strings.TrimSpace(h)
}

// Extracts the aliases from a Hugo header string
func extractAliasesFromHeader(h string) ([]string, error) {
	var aliases []string
	var data map[string]interface{}
	err := yaml.Unmarshal([]byte(h), &data)
	if err != nil {
		return aliases, err
	}
	x, found := data["aliases"]
	if !found {
		return aliases, nil
	}
	y := x.([]interface{})
	for _, z := range y {
		aliases = append(aliases, z.(string))
	}
	return aliases, nil
}
