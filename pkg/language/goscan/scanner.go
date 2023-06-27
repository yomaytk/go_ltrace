package goscan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"

	uutil "github.com/yomaytk/go_ltrace/util"
	gity "github.com/yomaytk/go_ltrace/vulndb/gitrepo/types"
	"golang.org/x/xerrors"
)

func getParamTypes(expr ast.Expr) (string, error) {
	switch e_ty := expr.(type) {
	case *ast.Ident:
		return e_ty.Name, nil
	case *ast.SelectorExpr:
		ttype, err := getParamTypes(e_ty.X)
		uutil.ErrFatal(err)
		return ttype + "." + e_ty.Sel.Name, nil
	case *ast.StarExpr:
		ttype, err := getParamTypes(e_ty.X)
		uutil.ErrFatal(err)
		return "*" + ttype, nil
	case *ast.InterfaceType:
		methods := ""
		method_list := e_ty.Methods.List
		for i := 0; i < len(method_list); i++ {
			ttype, err := getParamTypes(method_list[i].Type)
			uutil.ErrFatal(err)
			methods += ttype
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
			ttype, err := getParamTypes(param_list[i].Type)
			uutil.ErrFatal(err)
			params += ttype
			if i < len(param_list)-1 {
				params += ", "
			}
		}
		// get return types
		results := ""
		result_list := e_ty.Results.List
		for i := 0; i < len(result_list); i++ {
			ttype, err := getParamTypes(result_list[i].Type)
			uutil.ErrFatal(err)
			results += ttype
			if i < len(result_list)-1 {
				results += ", "
			}
		}
		return fmt.Sprintf("func (%v) %v", params, results), nil
	case *ast.MapType:
		// get key
		key, err := getParamTypes(e_ty.Key)
		uutil.ErrFatal(err)
		value, err := getParamTypes(e_ty.Value)
		uutil.ErrFatal(err)
		return fmt.Sprintf("map[%v]%v", key, value), nil
	case *ast.StructType:
		// get field
		fields := ""
		field_lists := e_ty.Fields.List
		for i := 0; i < len(field_lists); i++ {
			field_ttype, err := getParamTypes(field_lists[i].Type)
			uutil.ErrFatal(err)
			fields += field_ttype
			if i < len(field_lists)-1 {
				fields += ", "
			}
		}
		return fmt.Sprintf("struct {%v}", fields), nil
	case *ast.ArrayType:
		elem_ttype, err := getParamTypes(e_ty.Elt)
		uutil.ErrFatal(err)
		return fmt.Sprintf("[]%v", elem_ttype), nil
	case *ast.Ellipsis:
		elem_ttype, err := getParamTypes(e_ty.Elt)
		uutil.ErrFatal(err)
		return fmt.Sprintf("...%v", elem_ttype), nil
	default:
		return "", xerrors.Errorf("Bug unknown expression Type at getParamTypes.: '%v'\n", reflect.TypeOf(e_ty))
	}
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
			if params := fn.Type.Params; params != nil {
				for _, param_type := range params.List {
					param_type_name, err := getParamTypes(param_type.Type)
					uutil.ErrFatal(err)
					param_types = append(param_types, param_type_name)
				}
			}

			// get return types
			return_types := []string{}
			if returns := fn.Type.Results; returns != nil {
				for _, return_type := range returns.List {
					return_type_name, err := getParamTypes(return_type.Type)
					uutil.ErrFatal(err)
					return_types = append(return_types, return_type_name)
				}
			}

			// struct method
			struct_type := ""
			if fn.Recv != nil {
				struct_type, err = getParamTypes(fn.Recv.List[0].Type)
				uutil.ErrFatal(err)
			}

			func_location := gity.NewFuncLocation(func_name, struct_type, param_types, return_types, start_line, end_line)
			func_locations = append(func_locations, func_location)
		}
	}

	return func_locations, nil
}
