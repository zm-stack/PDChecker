package rule

import (
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// InvokeChaincodeRule lints cross chaincode invocation.
type InvokeChaincodeRule struct{}

// Name returns the rule name.
func (i *InvokeChaincodeRule) Name() string {
	return "chaincode-cross-channel"
}

// Apply applies the rule to given file.
func (i *InvokeChaincodeRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if selectorExpr.Sel.Name == "InvokeChaincode" {
					failure := lint.Failure{
						Failure:    "Chaincode invocation found. Do not attempt to change state in the invoked chaincode of a different channel.",
						RuleName:   "chaincode-cross-channel",
						Category:   "chaincode",
						Node:       callExpr,
						Confidence: 1.0,
					}
					failures = append(failures, failure)
				}
			}
		}
		return true
	})
	return failures
}
