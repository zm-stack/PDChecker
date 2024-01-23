package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// RetPrivacyLeakageRule lints privacy leakage of return value in Fabric chaincode.
type RetPrivacyLeakageRule struct{}

// Name returns the rule name.
func (i *RetPrivacyLeakageRule) Name() string {
	return "chaincode-privacy-leakage-in-ret"
}

// Apply applies the rule to given file.
func (i *RetPrivacyLeakageRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var getPrivateCalled bool
	var privateQuerys = []string{"GetPrivateData", "GetPrivateDataByPartialCompositeKey", "GetPrivateDataByRange", "GetPrivateDataQueryResult"}
	var updateOp = []string{"PutState", "PutPrivateData", "DelPrivateData", "PurgePrivateData"}
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			ast.Inspect(node, func(n ast.Node) bool {
				if callExpr, ok := n.(*ast.CallExpr); ok {
					if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						for _, fname := range privateQuerys {
							if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
								getPrivateCalled = true
							}
						}
						for _, fname := range updateOp {
							if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
								if getPrivateCalled {
									failure := lint.Failure{
										Failure:    fmt.Sprintf("Privacy leakage in return. The query of private data should be read-only"),
										RuleName:   "chaincode-privacy-leakage-in-ret",
										Category:   "chaincode",
										Node:       callExpr,
										Confidence: 1.0,
									}
									failures = append(failures, failure)
								}
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
