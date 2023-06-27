package gittypes

type FuncLocation struct {
	FuncName    string   `json:"name"`
	ParamTypes  []string `json:"param_types"`
	ReturnTypes []string `json:"return_types"`
	StructType  string   `json:"struct_type"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
}

func NewFuncLocation(func_name string, param_types []string, return_types []string, struct_type string, start_line int, end_line int) FuncLocation {
	return FuncLocation{func_name, param_types, return_types, struct_type, start_line, end_line}
}
