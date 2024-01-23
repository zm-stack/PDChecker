package rule

import (
	"fmt"
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// UnusedParamRule lints unused params in functions.
type UnCheckedParamRule struct{}

// Name returns the rule name.
func (*UnCheckedParamRule) Name() string {
	return "unchecked-parameter"
}

// Apply applies the rule to given file.
func (*UnCheckedParamRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	for _, node := range file.AST.Decls {
		switch fun := node.(type) {
		case *ast.FuncDecl:
			params := retrieveNamedParams(fun.Type.Params)
			if len(params) < 1 {
				return nil // skip, func without parameters
			}
			if fun.Body == nil {
				return nil // skip, is a function prototype
			}
			ast.Inspect(fun.Body, func(n ast.Node) bool {
				if ifExpr, ok := n.(*ast.IfStmt); ok {
					// inspect the func body looking for IfStmt to parameters
					fselect := func(n ast.Node) bool {
						ident, isAnID := n.(*ast.Ident)
						if !isAnID {
							return false
						}
						_, isAParam := params[ident.Obj]
						if isAParam {
							params[ident.Obj] = false // mark as used
						}
						return false
					}
					_ = pick(ifExpr.Cond, fselect)
				}
				return true
			})
			for _, p := range fun.Type.Params.List {
				for _, n := range p.Names {
					if params[n.Obj] {
						failure := lint.Failure{
							Failure:    fmt.Sprintf("parameter '%s' seems to be unchecked.", n.Name),
							RuleName:   "unchecked-parameter",
							Category:   "bad practice",
							Node:       n,
							Confidence: 1.0,
						}
						failures = append(failures, failure)
					}
				}
			}
		}
	}
	return failures
}
