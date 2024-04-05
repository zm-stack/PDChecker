package rule

import (
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// RetPrivacyLeakageRule lints privacy leakage of return value in Fabric chaincode.
type RetPrivacyLeakageRule struct{}

// Name returns the rule name.
func (i *RetPrivacyLeakageRule) Name() string {
	return "chaincode-privacy-ret"
}

// Apply applies the rule to given file.
func (i *RetPrivacyLeakageRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	var privateQuerys = []string{"GetTransient", "GetPrivateData", "GetPrivateDataByPartialCompositeKey", "GetPrivateDataByRange", "GetPrivateDataQueryResult"}
	var updateOp = []string{"PutState", "PutPrivateData", "DelPrivateData", "PurgePrivateData"}
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			var getPrivateCalled, updateCalled bool
			taintVars := make(map[string]struct{})
			ast.Inspect(node, func(n ast.Node) bool {
				if Assign, ok := n.(*ast.AssignStmt); ok {
					if callExpr, ok := Assign.Rhs[0].(*ast.CallExpr); ok {
						if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
							for _, fname := range privateQuerys {
								if strings.Compare(selectorExpr.Sel.Name, fname) == 0 {
									getPrivateCalled = true
									// 污点标记
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
			// 污点传播
			if getPrivateCalled && updateCalled {
				ast.Inspect(node, func(n ast.Node) bool {
					if Assign, ok := n.(*ast.AssignStmt); ok {
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
						// 漏洞检测
					} else if ret, ok := n.(*ast.ReturnStmt); ok {
						ast.Inspect(ret, func(n ast.Node) bool {
							if ident, ok := n.(*ast.Ident); ok {
								if _, ok := taintVars[ident.Name]; ok {
									failure := lint.Failure{
										Failure:    "Privacy leakage in return. The query of private data should be read-only",
										RuleName:   "chaincode-privacy-ret",
										Category:   "chaincode",
										Node:       ret,
										Confidence: 1.0,
									}
									failures = append(failures, failure)
								}
							}
							return true
						})

					}

					return true
				})
			}
		}
	}

	return failures
}
