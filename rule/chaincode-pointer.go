package rule

import (
	"go/ast"
	"go/token"

	"github.com/mgechev/revive/lint"
)

// PointerRule lints pointer used in Fabric chaincode.
type PointerRule struct{}

// Name returns the rule name.
func (*PointerRule) Name() string {
	return "chaincode-pointer"
}

// Apply applies the rule to given file.
func (p *PointerRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	// detect & as a unary operator
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if expr, ok := n.(*ast.UnaryExpr); ok {
			if expr.Op == token.AND {
				failure := lint.Failure{
					Failure:    "& detected. The address is random, which may lead to consensus errors.",
					RuleName:   "chaincode-pointer",
					Category:   "chaincode",
					Node:       expr,
					Confidence: 1.0,
				}
				failures = append(failures, failure)
			}
		}
		return true
	})
	// detect * as a pointer operator except in function receiver, parameters
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			if funcDecl.Type.Results != nil {
				ast.Inspect(funcDecl.Type.Results, func(n ast.Node) bool {
					if expr, ok := n.(*ast.StarExpr); ok {
						failure := lint.Failure{
							Failure:    "* detected in return value. Pointer is not recommended in chaincode if not necessary.",
							RuleName:   "chaincode-pointer",
							Category:   "chaincode",
							Node:       expr,
							Confidence: 1.0,
						}
						failures = append(failures, failure)
					}
					return true
				})
			}
			ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
				if expr, ok := n.(*ast.StarExpr); ok {
					failure := lint.Failure{
						Failure:    "* detected. Pointer is not recommended in chaincode if not necessary.",
						RuleName:   "chaincode-pointer",
						Category:   "chaincode",
						Node:       expr,
						Confidence: 1.0,
					}
					failures = append(failures, failure)
				}
				return true
			})
			return false
		} else {
			if expr, ok := n.(*ast.StarExpr); ok {
				failure := lint.Failure{
					Failure:    "* detected. Pointer is not recommended in chaincode if not necessary.",
					RuleName:   "chaincode-pointer",
					Category:   "chaincode",
					Node:       expr,
					Confidence: 1.0,
				}
				failures = append(failures, failure)
			}
		}
		return true
	})
	return failures
}
