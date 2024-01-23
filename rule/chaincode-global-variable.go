package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/mgechev/revive/lint"
)

// GlobalVariableRule lints global variables used in Fabric chaincode.
type GlobalVariableRule struct{}

// Name returns the rule name.
func (*GlobalVariableRule) Name() string {
	return "chaincode-global-variable"
}

// Apply applies the rule to given file.
func (*GlobalVariableRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	// global variables declared outside of functions are recorded in Decls[]
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.GenDecl:
			genDecl := node.(*ast.GenDecl)
			if genDecl.Tok == token.VAR {
				for _, spec := range genDecl.Specs {
					if vspec, ok := spec.(*ast.ValueSpec); ok {
						// Exclude the const, only detect variables
						for _, name := range vspec.Names {
							failure := lint.Failure{
								Failure:    fmt.Sprintf("Global variable found: %v, which may lead to consensus error.", name.Name),
								RuleName:   "chaincode-global-variable",
								Category:   "chaincode",
								Node:       vspec,
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
