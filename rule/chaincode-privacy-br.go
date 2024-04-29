package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/mgechev/revive/lint"
)

// BrPrivacyLeakageRule lints privacy leakage in br statement in Fabric chaincode.
type BrPrivacyLeakageRule struct{}

// Name returns the rule name.
func (i *BrPrivacyLeakageRule) Name() string {
	return "chaincode-privacy-br"
}

// Apply applies the rule to given file.
func (i *BrPrivacyLeakageRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var privateQuerys = []string{"GetTransient", "GetPrivateData", "GetPrivateDataByPartialCompositeKey", "GetPrivateDataByRange", "GetPrivateDataQueryResult"}
	var updateOp = []string{"PutState", "PutPrivateData", "DelPrivateData", "PurgePrivateData"}

	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			var getPrivateCalled, updateCalled bool
			taintVars := make(map[string]struct{})
			ast.Inspect(node, func(n ast.Node) bool {
				// 污点分析
				if Assign, ok := n.(*ast.AssignStmt); ok {
					// 污点标记
					if callExpr, ok := Assign.Rhs[0].(*ast.CallExpr); ok {
						if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
							if strings.Compare(selectorExpr.Sel.Name, "PutPrivateData") == 0 {
								if ident, ok := callExpr.Args[2].(*ast.Ident); ok {
									taintVars[ident.Name] = struct{}{}
								}
							}
							for _, fname := range privateQuerys {
								if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
									getPrivateCalled = true
									if ident, ok := Assign.Lhs[0].(*ast.Ident); ok {
										taintVars[ident.Name] = struct{}{}
									}
								}
							}
							for _, fname := range updateOp {
								if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
									updateCalled = true
								}
							}
						}
					}
				}
				return true
			})

			//污点传播
			if getPrivateCalled && updateCalled {
				ast.Inspect(node, func(n ast.Node) bool {
					var AssginNode *ast.AssignStmt
					var AssginFound bool
					if RangeStmt, ok := n.(*ast.RangeStmt); ok {
						if RangeKey, ok := RangeStmt.Key.(*ast.Ident); ok {
							if Assign, ok := RangeKey.Obj.Decl.(*ast.AssignStmt); ok {
								AssginNode = Assign
								AssginFound = true
							}

						}
					} else if Assign, ok := n.(*ast.AssignStmt); ok {
						AssginNode = Assign
						AssginFound = true
					}
					if AssginFound {
						var tainted bool
						for _, RhsExpr := range AssginNode.Rhs {
							ast.Inspect(RhsExpr, func(n ast.Node) bool {
								if ident, ok := n.(*ast.Ident); ok {
									if _, ok := taintVars[ident.Name]; ok {
										tainted = true
									}
								}
								return true
							})
						}
						if tainted {
							for _, LhsExpr := range AssginNode.Lhs {
								ast.Inspect(LhsExpr, func(n ast.Node) bool {
									if ident, ok := n.(*ast.Ident); ok {
										if !strings.EqualFold(ident.Name, "err") && !strings.EqualFold(ident.Name, "error") {
											taintVars[ident.Name] = struct{}{}
										}
									}
									return true
								})
							}
							// 处理	json.Unmarshal的情况
							if callExpr, ok := AssginNode.Rhs[0].(*ast.CallExpr); ok {
								if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
									if selectorExpr.Sel.Name == "Unmarshal" {
										ast.Inspect(callExpr.Args[1], func(n ast.Node) bool {
											if ident, ok := n.(*ast.Ident); ok {
												taintVars[ident.Name] = struct{}{}
											}
											return true
										})
									}
								}
							}
						}
					}
					// 漏洞检测
					if ifStmt, ok := n.(*ast.IfStmt); ok {
						failures = handleExpr(ifStmt.Cond, taintVars, failures)
					} else if switchStmt, ok := n.(*ast.SwitchStmt); ok {
						if ident, ok := switchStmt.Tag.(*ast.Ident); ok {
							if _, ok := taintVars[ident.Name]; ok {
								failure := lint.Failure{
									Failure:    "Private data applied to the branch condition, please check whether privacy leakage will occur.",
									RuleName:   "chaincode-privacy-br",
									Category:   "chaincode",
									Node:       switchStmt,
									Confidence: 1.0,
								}
								failures = append(failures, failure)
							}
						}
					}
					return true
				})
			}
		}
	}
	return failures
}

func handleExpr(expr ast.Expr, taintVars map[string]struct{}, failures []lint.Failure) []lint.Failure {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.LAND || e.Op == token.LOR {
			failures = handleExpr(e.X, taintVars, failures)
			failures = handleExpr(e.Y, taintVars, failures)
		} else {
			binaryExpr := expr.(*ast.BinaryExpr)
			N_nil_0 := true
			if ident, ok := binaryExpr.Y.(*ast.Ident); ok {
				if ident.Name == "nil" {
					N_nil_0 = false
				}
			} else if basicLit, ok := binaryExpr.Y.(*ast.BasicLit); ok {
				if basicLit.Value == "0" || basicLit.Value == "\"\"" {
					N_nil_0 = false
				}
			}
			if N_nil_0 {
				ast.Inspect(binaryExpr, func(n ast.Node) bool {
					if ident, ok := n.(*ast.Ident); ok {
						if _, ok := taintVars[ident.Name]; ok {
							failure := lint.Failure{
								Failure:    "Private data applied to the branch condition, please check whether privacy leakage will occur.",
								RuleName:   "chaincode-privacy-br",
								Category:   "chaincode",
								Node:       expr,
								Confidence: 1.0,
							}
							failures = append(failures, failure)
						}
					}
					return true
				})
			}
		}
	case *ast.ParenExpr:
		failures = handleExpr(e.X, taintVars, failures)
	}
	return failures
}
