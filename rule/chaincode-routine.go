package rule

import (
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// Goroutines Rule detects the use of goroutines
type GoRoutineRule struct{}

type lintGoRoutines struct {
	file      *lint.File
	onFailure func(lint.Failure)
}

// Name returns the rule name.
func (r *GoRoutineRule) Name() string {
	return "chaincode-routine"
}

// Apply applies the rule to given file.
func (r *GoRoutineRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	walker := lintGoRoutines{
		file: file,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}

	ast.Walk(walker, file.AST)
	return failures
}

// AST Traversal
func (w lintGoRoutines) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	// detect usage of goroutine
	case *ast.GoStmt:
		w.onFailure(lint.Failure{
			Failure:    "concurrent operation detected, which are not recommended in the chaincode.",
			RuleName:   "chaincode-routine",
			Category:   "chaincode",
			Node:       n,
			Confidence: 1.0,
		})
	}
	return w
}
