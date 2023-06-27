package gittypes

type FuncLocation struct {
	FuncName    string   `json:"name"`
	StructType  string   `json:"struct_type"`
	ParamTypes  []string `json:"param_types"`
	ReturnTypes []string `json:"return_types"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
}

func NewFuncLocation(func_name string, struct_type string, param_types []string, return_types []string, start_line int, end_line int) FuncLocation {
	return FuncLocation{func_name, struct_type, param_types, return_types, start_line, end_line}
}
