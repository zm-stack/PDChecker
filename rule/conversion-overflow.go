package rule

import (
	"go/ast"

	"github.com/mgechev/revive/lint"
)

// ConversionOverflowRule lints overflow in calculation.
type ConversionOverflowRule struct{}

type lintConversionOverflow struct {
	file      *lint.File
	onFailure func(lint.Failure)
}

// Name returns the rule name.
func (*ConversionOverflowRule) Name() string {
	return "conversion-overflow"
}

const INT = 1
const UINT = 0
const ELSE = -1

// Apply applies the rule to given file.
func (*ConversionOverflowRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	walker := lintConversionOverflow{
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
func (w lintConversionOverflow) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {
	case *ast.CallExpr:
		if fun, ok := n.Fun.(*ast.Ident); ok {
			convType, convSize := isConv(fun.Name)
			if convType != -1 {
				if arg, ok := n.Args[0].(*ast.Ident); ok {
					argType, argSize := isConv(w.file.Pkg.TypesInfo().Types[arg].Type.Underlying().String())
					if convType == argType {
						if convSize < argSize {
							w.onFailure(lint.Failure{
								Failure:    "Converting a large integer to a small integer. Please use functions with overflow check. \n github.com/lunemec/as or github.com/rung/go-safecast.",
								RuleName:   "conversion-overflow",
								Category:   "logic",
								Node:       n,
								Confidence: 1.0,
							})
						}
					} else if convType == 0 && argType == 1 {
						w.onFailure(lint.Failure{
							Failure:    "Converting a signed integer to an unsigned integer. Please use functions with overflow check. \n github.com/lunemec/as or github.com/rung/go-safecast.",
							RuleName:   "conversion-overflow",
							Category:   "logic",
							Node:       n,
							Confidence: 1.0,
						})
					} else if convType == 1 && argType == 0 {
						if convSize < 2*argSize {
							w.onFailure(lint.Failure{
								Failure:    "Converting a unsigned integer to a small signed integer. Please use functions with overflow check. \n github.com/lunemec/as or github.com/rung/go-safecast.",
								RuleName:   "conversion-overflow",
								Category:   "logic",
								Node:       n,
								Confidence: 1.0,
							})
						}
					}
				}
			}

		}
	}
	return w
}

func isConv(str string) (int, uint) {
	switch str {
	case "int":
		return INT, 64
	case "int8":
		return INT, 8
	case "int16":
		return INT, 16
	case "int32":
		return INT, 32
	case "int64":
		return INT, 64
	case "uint":
		return UINT, 64
	case "uint8":
		return UINT, 8
	case "uint16":
		return UINT, 16
	case "uint32":
		return UINT, 32
	case "uint64":
		return UINT, 64
	default:
		return ELSE, 0
	}
}
