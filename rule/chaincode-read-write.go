package rule

import (
	"go/ast"
	"strings"

	"github.com/mgechev/revive/lint"
)

// ReadAfterWriteRule lints write and read opreations on the same key in Fabric chaincode.
type ReadAfterWriteRule struct{}

// Name returns the rule name.
func (i *ReadAfterWriteRule) Name() string {
	return "chaincode-read-write"
}

// Apply applies the rule to given file.
func (i *ReadAfterWriteRule) Apply(file *lint.File, _ lint.Arguments) []lint.Failure {
	var failures []lint.Failure
	// Check each function separately
	for _, node := range file.AST.Decls {
		switch node.(type) {
		case *ast.FuncDecl:
			var writeKeys, writeprivateKeys []string
			var putStateCalled, putPrivateCalled bool
			ast.Inspect(node, func(n ast.Node) bool {
				if callExpr, ok := n.(*ast.CallExpr); ok {
					if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if strings.Compare(selectorExpr.Sel.Name, "PutState") == 0 {
							putStateCalled = true
							var writeKey string
							if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
								writeKey = ident.Name
							} else if basicLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
								writeKey = basicLit.Value
							} else if selectorExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
								writeKey = selectorExpr.Sel.Name
							}
							writeKeys = append(writeKeys, writeKey)
						}
						if strings.Compare(selectorExpr.Sel.Name, "GetState") == 0 {
							if putStateCalled {
								var readKey string
								if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
									readKey = ident.Name
								} else if basicLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
									readKey = basicLit.Value
								} else if selectorExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
									readKey = selectorExpr.Sel.Name
								}
								for _, key := range writeKeys {
									if readKey != "" && strings.Compare(key, readKey) == 0 {
										failure := lint.Failure{
											Failure:    "Read after write detected. The read value is outdated.",
											RuleName:   "chaincode-read-write",
											Category:   "chaincode",
											Node:       callExpr,
											Confidence: 1.0,
										}
										failures = append(failures, failure)
									}
								}
							}
						}
						if selectorExpr.Sel.Name == "PutPrivateData" {
							putPrivateCalled = true
							var writePrivateCollection, writePrivateKey string
							if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
								writePrivateCollection = ident.Name
							} else if basicLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
								writePrivateCollection = basicLit.Value
							} else if selectorExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
								writePrivateCollection = selectorExpr.Sel.Name
							}
							if ident, ok := callExpr.Args[1].(*ast.Ident); ok {
								writePrivateKey = ident.Name
							} else if basicLit, ok := callExpr.Args[1].(*ast.BasicLit); ok {
								writePrivateKey = basicLit.Value
							} else if selectorExpr, ok := callExpr.Args[1].(*ast.SelectorExpr); ok {
								writePrivateKey = selectorExpr.Sel.Name
							}
							writeprivateKeys = append(writeprivateKeys, writePrivateCollection+writePrivateKey)
						}
						if selectorExpr.Sel.Name == "GetPrivateData" {
							if putPrivateCalled {
								var readPrivateCollection, readPrivateKey string
								if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
									readPrivateCollection = ident.Name
								} else if basicLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
									readPrivateCollection = basicLit.Value
								} else if selectorExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
									readPrivateCollection = selectorExpr.Sel.Name
								}
								if ident, ok := callExpr.Args[1].(*ast.Ident); ok {
									readPrivateKey = ident.Name
								} else if basicLit, ok := callExpr.Args[1].(*ast.BasicLit); ok {
									readPrivateKey = basicLit.Value
								} else if selectorExpr, ok := callExpr.Args[1].(*ast.SelectorExpr); ok {
									readPrivateKey = selectorExpr.Sel.Name
								}
								for _, key := range writeprivateKeys {
									if strings.Compare(key, readPrivateCollection+readPrivateKey) == 0 {
										failure := lint.Failure{
											Failure:    "Read after write detected. The read value is outdated.",
											RuleName:   "chaincode-read-write",
											Category:   "chaincode",
											Node:       callExpr,
											Confidence: 1.0,
										}
										failures = append(failures, failure)
									}
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	return failures
}
