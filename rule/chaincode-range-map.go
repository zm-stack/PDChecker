package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// RangeOverMapRule lints range over map in Fabric chaincode.
type RangeOverMapRule struct{}

type lintRangeOverMap struct {
	file      *lint.File
	onFailure func(lint.Failure)
}

// Name returns the rule name.
func (r *RangeOverMapRule) Name() string {
	return "chaincode-range-over-map"
}

// Apply applies the rule to given file.
func (r *RangeOverMapRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	walker := lintRangeOverMap{
		file: file,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}
	file.Pkg.TypeCheck()
	ast.Walk(walker, file.AST)
	return failures
}

// AST traversal logic
func (w lintRangeOverMap) Visit(node ast.Node) ast.Visitor {
	switch node := node.(type) {
	case *ast.RangeStmt:
		if rangeObj, ok := w.file.Pkg.TypesInfo().Types[node.X]; ok {
			if strings.Contains(rangeObj.Type.String(), "map") {
				w.onFailure(lint.Failure{
					Failure:    fmt.Sprintf("Range over map returns pair randomly. Please ensure it does not result in inconsistent result."),
					RuleName:   "chaincode-range-over-map",
					Category:   "chaincode",
					Node:       node,
					Confidence: 1.0,
				})
			}
		}
	}
	return w
}
