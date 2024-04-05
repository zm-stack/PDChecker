package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/mgechev/revive/lint"
)

// BlackImportRule lints black package imported in Fabric chaincode.
type BlackImportRule struct{}

// Name returns the rule name.
func (*BlackImportRule) Name() string {
	return "chaincode-blacklist-import"
}

// Apply applies the rule to given file.
func (*BlackImportRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	// Unsafe or potentially consensus-breaking package
	var blacklistedImports = []string{"\"math/rand\"", "\"crypto/rand\"", "\"time\"", "\"io\"", "\"os\"", "\"net\"",
		"\"crypto/des\"", "\"crypto/md5\"", "\"crypto/sha1\"", "\"crypto/rc4\""}
	var failures []lint.Failure
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.GenDecl:
			genDecl := node.(*ast.GenDecl)
			if genDecl.Tok == token.IMPORT {
				for _, importSpec := range genDecl.Specs {
					pkg := importSpec.(*ast.ImportSpec).Path.Value
					for _, p := range blacklistedImports {
						if strings.HasPrefix(pkg, p) {
							failure := lint.Failure{
								Failure:    fmt.Sprintf("Blacklisted package found: %v. This package is not secure or may lead to consensus errors.", pkg),
								RuleName:   "chaincode-blacklist-import",
								Category:   "chaincode",
								Node:       importSpec,
								Confidence: 1.0,
							}
							failures = append(failures, failure)
						}
					}
					if strings.HasPrefix(pkg, "\"github") {
						if !(strings.HasPrefix(pkg, "\"github.com/hyperledger")) {
							failure := lint.Failure{
								Failure:    fmt.Sprintf("External library found: %v. Please ensure this package does not return inconsistent results.", pkg),
								RuleName:   "chaincode-blacklist-import",
								Category:   "chaincode",
								Node:       importSpec,
								Confidence: 1.0,
							}
							failures = append(failures, failure)
						}
					}
				}
			}
		}
	}
	return failures
}
