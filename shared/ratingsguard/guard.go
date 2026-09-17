// Package ratingsguard detects handwritten rating ladders in Go syntax.
// It reports definitions, not legitimate source-to-domain policies (which are
// documented as explicit exceptions in the repository guard manifest).
package ratingsguard

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

type Violation struct {
	Line           int
	Symbol, Reason string
	Fingerprint    string
}

var words = map[string]bool{"critical": true, "high": true, "medium": true, "med": true, "low": true, "info": true, "informational": true, "excellent": true, "good": true, "fair": true, "poor": true, "failing": true, "weak": true, "acceptable": true, "strong": true, "recommended": true}
var sqlRank = regexp.MustCompile(`(?i)\bWHEN\s+'(?:critical|high|medium|low|info)'\s+THEN\s+[0-9]+`)
var sqlGrade = regexp.MustCompile(`(?i)\bWHEN\s+[^;]*?(?:>=|>|<=|<)\s*[0-9]+\s+THEN\s+'(?:critical|high|medium|low|info|excellent|good|fair|poor|failing)'`)
var sqlRisk = regexp.MustCompile(`(?i)\brisk_score\s*(?:>=|>|<=|<)\s*[1-9][0-9]*`)

// word also recognizes canonical constant references, so changing a spelling
// from "critical" to severity.Critical does not hide a copied ladder.
func word(expr ast.Expr) string {
	var value string
	switch x := expr.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			value, _ = strconv.Unquote(x.Value)
		}
	case *ast.Ident:
		value = x.Name
	case *ast.SelectorExpr:
		value = x.Sel.Name
	}
	value = strings.ToLower(value)
	value = strings.TrimPrefix(value, "severity")
	if words[value] {
		return value
	}
	return ""
}
func numeric(expr ast.Expr) bool {
	if word(expr) != "" {
		return false
	}
	switch x := expr.(type) {
	case *ast.BasicLit:
		return x.Kind == token.INT || x.Kind == token.FLOAT
	case *ast.Ident:
		return x.Name != "true" && x.Name != "false" && x.Name != "nil"
	case *ast.SelectorExpr:
		return true
	}
	return false
}
func stringExpression(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			v, _ := strconv.Unquote(x.Value)
			return v
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return stringExpression(x.X) + stringExpression(x.Y)
		}
	case *ast.Ident, *ast.SelectorExpr:
		return word(expr)
	}
	return ""
}

func Inspect(filename string, source []byte) ([]Violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, source, 0)
	if err != nil {
		return nil, err
	}
	var out []Violation
	check := func(name string, node ast.Node) {
		found := map[string]bool{}
		comparisons := 0
		numericKeys := 0
		rankCases := 0
		numericResults := 0
		constructor := false
		sql := false
		table := false
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ReturnStmt:
				for _, expr := range x.Results {
					if lit, ok := expr.(*ast.BasicLit); ok && (lit.Kind == token.INT || lit.Kind == token.FLOAT) {
						numericResults++
					}
				}
			case *ast.AssignStmt:
				for _, expr := range x.Rhs {
					if lit, ok := expr.(*ast.BasicLit); ok && (lit.Kind == token.INT || lit.Kind == token.FLOAT) {
						numericResults++
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					s, _ := strconv.Unquote(x.Value)
					if words[strings.ToLower(s)] {
						found[strings.ToLower(s)] = true
					}
					if len(sqlRank.FindAllString(s, -1)) >= 3 || sqlRisk.MatchString(s) || len(sqlGrade.FindAllString(s, -1)) >= 2 {
						sql = true
					}
				}
			case *ast.BinaryExpr:
				if x.Op == token.ADD && (len(sqlRank.FindAllString(stringExpression(x), -1)) >= 3 || len(sqlGrade.FindAllString(stringExpression(x), -1)) >= 2) {
					sql = true
				}
				switch x.Op {
				case token.GEQ, token.GTR, token.LEQ, token.LSS:
					comparisons++
				}
			case *ast.Ident, *ast.SelectorExpr:
				if expr, ok := n.(ast.Expr); ok {
					if w := word(expr); w != "" {
						found[w] = true
					}
				}
			case *ast.CompositeLit:
				entries := 0
				for _, elt := range x.Elts {
					hasWord, hasNumber := false, false
					ast.Inspect(elt, func(child ast.Node) bool {
						if expr, ok := child.(ast.Expr); ok {
							hasWord = hasWord || word(expr) != ""
						}
						if lit, ok := child.(*ast.BasicLit); ok {
							hasNumber = hasNumber || lit.Kind == token.INT || lit.Kind == token.FLOAT
						}
						if kv, ok := child.(*ast.KeyValueExpr); ok {
							if key, ok := kv.Key.(*ast.Ident); ok {
								switch strings.ToLower(key.Name) {
								case "min", "max", "rank", "threshold", "score":
									hasNumber = hasNumber || numeric(kv.Value)
								}
							}
						}
						return true
					})
					if hasWord && hasNumber {
						entries++
					}
				}
				table = table || entries >= 3
				typeExpr := x.Type
				if array, ok := typeExpr.(*ast.ArrayType); ok {
					typeExpr = array.Elt
				}
				typeName := stringExpression(typeExpr)
				if ident, ok := typeExpr.(*ast.Ident); ok {
					typeName = ident.Name
				}
				if selector, ok := typeExpr.(*ast.SelectorExpr); ok {
					typeName = selector.Sel.Name
				}
				if strings.Contains(strings.ToLower(typeName), "band") || strings.Contains(strings.ToLower(typeName), "rung") {
					hasWord, hasNumber := false, false
					ast.Inspect(x, func(child ast.Node) bool {
						if expr, ok := child.(ast.Expr); ok {
							hasWord = hasWord || word(expr) != ""
							if lit, ok := expr.(*ast.BasicLit); ok {
								hasNumber = hasNumber || lit.Kind == token.INT || lit.Kind == token.FLOAT
							}
						}
						return true
					})
					table = table || (hasWord && hasNumber)
				}
			case *ast.KeyValueExpr:
				if word(x.Key) != "" && numeric(x.Value) {
					numericKeys++
				}
			case *ast.CaseClause:
				for _, expr := range x.List {
					for _, statement := range x.Body {
						if ret, ok := statement.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
							if (word(expr) != "" && numeric(ret.Results[0])) || (numeric(expr) && word(ret.Results[0]) != "") {
								rankCases++
							}
						}
					}
				}
			case *ast.CallExpr:
				name := ""
				switch fun := x.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				}
				if name == "FromRungs" && len(x.Args) >= 4 {
					constructor = true
				}
			}
			return true
		})
		reason := ""
		switch {
		case table:
			reason = "local rating table"
		case constructor:
			reason = "local risk ladder constructor"
		case sql:
			reason = "local SQL risk/severity ladder"
		case rankCases >= 3 || (len(found) >= 3 && numericResults >= 3):
			reason = "local severity rank switch"
		case len(found) >= 3 && comparisons >= 2:
			reason = "local numeric rating ladder"
		case numericKeys >= 3:
			reason = "local rating map"
		}
		if reason != "" {
			var normalized bytes.Buffer
			if err := printer.Fprint(&normalized, fset, node); err != nil {
				panic(err)
			}
			out = append(out, Violation{fset.Position(node.Pos()).Line, name, reason, fmt.Sprintf("%x", sha256.Sum256(normalized.Bytes()))})
		}
	}
	for _, decl := range file.Decls {
		switch x := decl.(type) {
		case *ast.FuncDecl:
			check(x.Name.Name, x)
		case *ast.GenDecl:
			thresholds := 0
			if x.Tok == token.CONST {
				for _, spec := range x.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok {
						for _, name := range value.Names {
							lower := strings.ToLower(name.Name)
							if strings.Contains(lower, "score") || strings.Contains(lower, "min") || strings.Contains(lower, "threshold") {
								for w := range words {
									if strings.Contains(lower, w) {
										for _, expr := range value.Values {
											if lit, ok := expr.(*ast.BasicLit); ok && (lit.Kind == token.INT || lit.Kind == token.FLOAT) {
												thresholds++
											}
										}
										break
									}
								}
							}
						}
					}
				}
			}
			if thresholds >= 3 {
				var normalized bytes.Buffer
				if err := printer.Fprint(&normalized, fset, x); err != nil {
					return nil, err
				}
				first := x.Specs[0].(*ast.ValueSpec).Names[0].Name
				out = append(out, Violation{fset.Position(x.Pos()).Line, "const:" + first, "local named rating boundaries", fmt.Sprintf("%x", sha256.Sum256(normalized.Bytes()))})
			}
			for _, spec := range x.Specs {
				if v, ok := spec.(*ast.ValueSpec); ok {
					for i, value := range v.Values {
						name := v.Names[0].Name
						if i < len(v.Names) {
							name = v.Names[i].Name
						}
						check(name, value)
					}
				}
			}
		}
	}
	return out, nil
}
