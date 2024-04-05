package rule

import (
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// BrPrivacyLeakageRule lints privacy leakage in br statement in Fabric chaincode.
type BrPrivacyLeakageRule struct {
}

// Name returns the rule name.
func (i *BrPrivacyLeakageRule) Name() string {
	return "chaincode-privacy-br"
}

// Apply applies the rule to given file.
func (i *BrPrivacyLeakageRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var privateQuerys = []string{"GetTransient", "GetPrivateData", "GetPrivateDataByPartialCompositeKey", "GetPrivateDataByRange", "GetPrivateDataQueryResult"}
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			var getPrivateCalled bool
			taintVars := make(map[string]struct{})

			ast.Inspect(node, func(n ast.Node) bool {
				// 污点分析
				if Assign, ok := n.(*ast.AssignStmt); ok {
					// 污点标记
					if callExpr, ok := Assign.Rhs[0].(*ast.CallExpr); ok {
						if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {

							for _, fname := range privateQuerys {
								if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
									getPrivateCalled = true
									if ident, ok := Assign.Lhs[0].(*ast.Ident); ok {
										taintVars[ident.Name] = struct{}{}
									}
								}
							}
						}
					}

					//污点传播
					if getPrivateCalled {
						var tainted bool
						for _, RhsExpr := range Assign.Rhs {
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
							if ident, ok := Assign.Lhs[0].(*ast.Ident); ok {
								if !strings.EqualFold(ident.Name, "err") && !strings.EqualFold(ident.Name, "error") {
									taintVars[ident.Name] = struct{}{}
								}
							}
							// 处理	json.Unmarshal的情况
							if callExpr, ok := Assign.Rhs[0].(*ast.CallExpr); ok {
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
				} else if ifStmt, ok := n.(*ast.IfStmt); ok {
					N_nil := true
					N_0 := true
					if binaryExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
						if ident, ok := binaryExpr.Y.(*ast.Ident); ok {
							if ident.Name == "nil" {
								N_nil = false
							}
						} else if basicLit, ok := binaryExpr.Y.(*ast.BasicLit); ok {
							if basicLit.Value == "0" {
								N_0 = false
							}
						}
					}
					if N_nil && N_0 {
						ast.Inspect(ifStmt.Cond, func(n ast.Node) bool {
							if ident, ok := n.(*ast.Ident); ok {
								if _, ok := taintVars[ident.Name]; ok {
									failure := lint.Failure{
										Failure:    "Private data applied to the branch condition, please check whether privacy leakage will occur.",
										RuleName:   "chaincode-privacy-br",
										Category:   "chaincode",
										Node:       ifStmt,
										Confidence: 1.0,
									}
									failures = append(failures, failure)
								}
							}
							return true

						})
					}
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
	return failures
}
