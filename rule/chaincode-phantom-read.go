package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// PhandomReadRule lints phandom read in Fabric chaincode.
type PhantomReadRule struct{}

// Name returns the rule name.
func (i *PhantomReadRule) Name() string {
	return "chaincode-phantom-read"
}

// Apply applies the rule to given file.
func (i *PhantomReadRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var blacklistedQuerys = []string{"GetQueryResult", "GetHistoryForKey", "GetPrivateDataQueryResult"}
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				for _, fname := range blacklistedQuerys {
					if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
						failure := lint.Failure{
							Failure:    fmt.Sprintf("This function does not perform phantom read checks. It is not recommended to use the results for state change."),
							RuleName:   "chaincode-phandom-read",
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
	return failures
}
