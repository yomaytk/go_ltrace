package goscan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	uutil "github.com/yomaytk/go_ltrace/util"
	gity "github.com/yomaytk/go_ltrace/vulndb/gitrepo/types"
	"golang.org/x/xerrors"
)

func getParamTypes(expr ast.Expr) (string, error) {
	switch e_ty := expr.(type) {
	case *ast.Ident:
		return e_ty.Name, nil
	case *ast.StarExpr:
		name, err := getParamTypes(e_ty.X)
		uutil.ErrFatal(err)
		return "*" + name, nil
	case *ast.InterfaceType:
		methods := ""
		method_list := e_ty.Methods.List
		for i := 0; i < len(method_list); i++ {
			name, err := getParamTypes(method_list[i].Type)
			uutil.ErrFatal(err)
			methods += name
			if i < len(method_list)-1 {
				methods += ", "
			}
		}
		return fmt.Sprintf("interface{%v}", methods), nil
	case *ast.FuncType:
		// get parameter types
		params := ""
		param_list := e_ty.Params.List
		for i := 0; i < len(param_list); i++ {
			name, err := getParamTypes(param_list[i].Type)
			uutil.ErrFatal(err)
			params += name
			if i < len(param_list)-1 {
				params += ", "
			}
		}
		// get return types
		results := ""
		result_list := e_ty.Results.List
		for i := 0; i < len(result_list); i++ {
			name, err := getParamTypes(result_list[i].Type)
			uutil.ErrFatal(err)
			results += name
			if i < len(result_list)-1 {
				results += ", "
			}
		}
		return fmt.Sprintf("func (%v) %v", params, results), nil
	}

	return "", xerrors.Errorf("Bug unknown expression Type at getParamTypes.\n")
}

func GetFuncLocation(content string) ([]gity.FuncLocation, error) {

	func_locations := []gity.FuncLocation{}

	// parse the file content and get function location
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", content, 0)
	uutil.ErrFatal(err)

	// get all func location
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			func_name := fn.Name.Name

			// the line of start and end of fuction
			start_line := fset.Position(fn.Pos()).Line
			end_line := fset.Position(fn.End()).Line

			// get paramter types
			param_types := []string{}
			for _, param_type := range fn.Type.Params.List {
				param_type_name, err := getParamTypes(param_type.Type)
				uutil.ErrFatal(err)
				param_types = append(param_types, param_type_name)
			}

			// get return types
			return_types := []string{}
			for _, return_type := range fn.Type.Results.List {
				return_type_name, err := getParamTypes(return_type.Type)
				uutil.ErrFatal(err)
				return_types = append(return_types, return_type_name)
			}

			// struct method
			struct_type := ""
			if fn.Recv != nil {
				expr := fn.Recv.List[0].Type
				if starExpr, ok := expr.(*ast.StarExpr); ok {
					struct_type = "*" + starExpr.X.(*ast.Ident).Name
				} else if ident, ok := expr.(*ast.Ident); ok {
					struct_type = ident.Name
				}
			}

			func_location := gity.NewFuncLocation(func_name, param_types, return_types, struct_type, start_line, end_line)
			func_locations = append(func_locations, func_location)
		}
	}

	return func_locations, nil
}
