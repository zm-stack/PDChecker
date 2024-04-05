package rule

import (
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// ArgPrivacyLeakageRule lints privacy leakage of arguments in Fabric chaincode.
type ArgPrivacyLeakageRule struct{}

// Name returns the rule name.
func (i *ArgPrivacyLeakageRule) Name() string {
	return "chaincode-privacy-arg"
}

// Apply applies the rule to given file.
func (i *ArgPrivacyLeakageRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			var getTransientCalled bool
			ast.Inspect(node, func(n ast.Node) bool {
				if callExpr, ok := n.(*ast.CallExpr); ok {
					if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if selectorExpr.Sel.Name == "GetTransient" {
							getTransientCalled = true
						}
						if selectorExpr.Sel.Name == "PutPrivateData" {
							if !getTransientCalled {
								failure := lint.Failure{
									Failure:    "Privacy leakage in arguments. The private data should be passed via GetTransient.",
									RuleName:   "chaincode-privacy-arg",
									Category:   "chaincode",
									Node:       callExpr,
									Confidence: 1.0,
								}
								failures = append(failures, failure)
							}
						}
					}
				}
				return true
			})
		}

	}
	return failures
}
