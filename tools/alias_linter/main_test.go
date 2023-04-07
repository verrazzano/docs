package main

import (
	"bufio"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

func Test_joinMapKeysToString(t *testing.T) {
	g := NewGomegaWithT(t)
	g.Expect(joinMapKeysToString(map[string]struct{}{}, "|")).Should(Equal(""))
	g.Expect(joinMapKeysToString(map[string]struct{}{"x": struct{}{}}, "|")).Should(Equal("x"))
	g.Expect(joinMapKeysToString(map[string]struct{}{
		"x": struct{}{},
		"y": struct{}{}}, "|")).Should(Equal("x|y"))
}

func Test_addOrUpdatePageInfoForFile(t *testing.T) {
	g := NewGomegaWithT(t)
	var info = make(map[string]map[string]struct{})
	g.Expect(info).Should(HaveLen(0))
	addOrUpdatePageInfoForFile("test-file-1", "test-branch-1", info)
	g.Expect(info).Should(HaveLen(1))
	g.Expect(info["test-file-1"]).Should(HaveKey("test-branch-1"))
	addOrUpdatePageInfoForFile("test-file-1", "test-branch-2", info)
	addOrUpdatePageInfoForFile("test-file-2", "test-branch-3", info)
	g.Expect(info).Should(HaveLen(2))
	g.Expect(info["test-file-1"]).Should(HaveKey("test-branch-1"))
	g.Expect(info["test-file-1"]).Should(HaveKey("test-branch-2"))
	g.Expect(info["test-file-2"]).Should(HaveKey("test-branch-3"))
}

func Test_convertFileNameToPageName(t *testing.T) {
	g := NewGomegaWithT(t)
	g.Expect(convertFileNameToPageName("")).Should(Equal(""))
	g.Expect(convertFileNameToPageName("/")).Should(Equal("/"))
	g.Expect(convertFileNameToPageName("//")).Should(Equal("/"))
	g.Expect(convertFileNameToPageName("/_index.md")).Should(Equal("/"))
	g.Expect(convertFileNameToPageName("path/_index.md")).Should(Equal("path"))
	g.Expect(convertFileNameToPageName("path/file.md")).Should(Equal("path/file"))
}

func Test_extractHeaderFromReader_withEmptyHeaderAndContent(t *testing.T) {
	g := NewGomegaWithT(t)
	s := `---
---
content-name: content-value`
	h := extractHeaderFromReader(bufio.NewReader(strings.NewReader(s)))
	g.Expect(h).Should(Equal(""))
}

func Test_extractHeaderFromReader_withEmptyHeaderAndNoContent(t *testing.T) {
	g := NewGomegaWithT(t)
	s := `---
---`
	h := extractHeaderFromReader(bufio.NewReader(strings.NewReader(s)))
	g.Expect(h).Should(Equal(""))
}

func Test_extractHeaderFromReader_withHeaderAndNoContent(t *testing.T) {
	g := NewGomegaWithT(t)
	s := `---
header-key: header-value
---`
	h := extractHeaderFromReader(bufio.NewReader(strings.NewReader(s)))
	g.Expect(h).Should(Equal("header-key: header-value"))
}

func Test_extractAliasesFromHeaderWithAliases(t *testing.T) {
	g := NewGomegaWithT(t)
	h := `
title: Access Verrazzano
description: "Information and tools to support operating Verrazzano"
weight: 4
draft: false
aliases:
  - /docs/operations
  - /docs/actions
`
	a, e := extractAliasesFromHeader(h)
	g.Expect(e).ShouldNot(HaveOccurred())
	g.Expect(a).Should(HaveLen(2))
	g.Expect(a).Should(ContainElements("/docs/operations", "/docs/actions"))
}

func Test_extractAliasesFromHeaderWithoutAliases(t *testing.T) {
	g := NewGomegaWithT(t)
	h := `
title: Access Verrazzano
description: "Information and tools to support operating Verrazzano"
weight: 4
draft: false
`
	a, e := extractAliasesFromHeader(h)
	g.Expect(e).ShouldNot(HaveOccurred())
	g.Expect(a).Should(HaveLen(0))
}

func Test_openRepo(t *testing.T) {
	g := NewGomegaWithT(t)

	// Expect error when both repoURL and repoDir are blank.
	a := argsType{
		repoURL: "",
		repoDir: "",
	}
	r, e := openRepo(&a)
	g.Expect(r).Should(BeNil())
	g.Expect(e).Should(HaveOccurred())
}
