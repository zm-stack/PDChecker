package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/mgechev/revive/lint"
)

// MathOverflowRule lints overflow in calculation.
type MathOverflowRule struct{}

type lintMathOverflow struct {
	file      *lint.File
	loops     []int
	onFailure func(lint.Failure)
}

// Name returns the rule name.
func (m *MathOverflowRule) Name() string {
	return "math-overflow"
}

// Apply applies the rule to given file.
func (m *MathOverflowRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var loopLines []int
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.ForStmt); ok {
			loopLines = append(loopLines, file.ToPosition(stmt.Pos()).Line)
		}
		return true
	})
	walker := lintMathOverflow{
		file:  file,
		loops: loopLines,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
	}
	file.Pkg.TypeCheck()
	ast.Walk(walker, file.AST)
	return failures
}

// AST traversal logic
func (w lintMathOverflow) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {

	case *ast.UnaryExpr:
		if n.Op == token.SUB {
			switch n.X.(type) {
			case *ast.BasicLit:
			default:
				if isIntType(w.file, n.X) {
					w.onFailure(lint.Failure{
						Failure:    "NegateInt overflow detected. Please use functions with overflow check.\n https://pkg.go.dev/github.com/bytom/bytom/math/checked.",
						RuleName:   "math-overflow",
						Category:   "logic",
						Node:       n,
						Confidence: 1.0,
					})
				}
			}
		}

	case *ast.BinaryExpr:
		if isIntType(w.file, n) {
			w.onFailure(lint.Failure{
				Failure:    "BinaryExpr overflow detected. Please use functions with overflow check.\n https://pkg.go.dev/github.com/bytom/bytom/math/checked.",
				RuleName:   "math-overflow",
				Category:   "logic",
				Node:       n,
				Confidence: 1.0,
			})
		}

	case *ast.ParenExpr:
		if isIntType(w.file, n.X) {
			w.onFailure(lint.Failure{
				Failure:    "ParenExpr overflow detected. Please use functions with overflow check.\n https://pkg.go.dev/github.com/bytom/bytom/math/checked.",
				RuleName:   "math-overflow",
				Category:   "logic",
				Node:       n,
				Confidence: 1.0,
			})
		}

	case *ast.IncDecStmt:
		flag := true
		if isIntType(w.file, n.X) {
			for _, loopLine := range w.loops {
				if w.file.ToPosition(n.Pos()).Line == loopLine {
					flag = false
				}
			}
			if flag {
				w.onFailure(lint.Failure{
					Failure:    "IncDecStmt overflow detected. Please use functions with overflow check.\n https://pkg.go.dev/github.com/bytom/bytom/math/checked.",
					RuleName:   "math-overflow",
					Category:   "logic",
					Node:       n,
					Confidence: 1.0,
				})
			}
		}

	case *ast.AssignStmt:
		if riskOperator(n.Tok) {
			if isIntType(w.file, n.Lhs[0]) {
				w.onFailure(lint.Failure{
					Failure:    "AssignStmt overflow detected. Please use functions with overflow check.\n https://pkg.go.dev/github.com/bytom/bytom/math/checked.",
					RuleName:   "math-overflow",
					Category:   "logic",
					Node:       n,
					Confidence: 1.0,
				})
			}
		}
	}
	return w
}

func riskOperator(op token.Token) bool {
	switch op {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.SHL:
		return true
	case token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN, token.SHL_ASSIGN:
		return true
	}
	return false
}

func isIntType(file *lint.File, expr ast.Expr) bool {
	exitRiskOperator := false
	if Operand, ok := expr.(*ast.Ident); ok {
		if file.Pkg.TypesInfo().Types[Operand].Type != nil {
			if OperandType := file.Pkg.TypesInfo().Types[Operand].Type.Underlying().String(); ok {
				if strings.HasPrefix(OperandType, "int") || strings.HasPrefix(OperandType, "uint") {
					return true
				}
			}
		}
	} else if Operand, ok := expr.(*ast.BasicLit); ok {
		if Operand.Kind == token.INT {
			return true
		}
	} else if binaryexpr, ok := expr.(*ast.BinaryExpr); ok {
		if riskOperator(binaryexpr.Op) {
			exitRiskOperator = true
		}
		if isIntType(file, binaryexpr.X) && isIntType(file, binaryexpr.Y) && exitRiskOperator {
			return true
		}
	} else if parenexpr, ok := expr.(*ast.ParenExpr); ok {
		if isIntType(file, parenexpr.X) {
			return true
		}
	}
	return false
}
