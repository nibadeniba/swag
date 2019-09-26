package swag

import (
	"fmt"
	"strings"
)

// CheckSchemaType checks if typeName is not a name of primitive type
func CheckSchemaType(typeName string) error {
	if !IsPrimitiveType(typeName) {
		return fmt.Errorf("%s is not basic types", typeName)
	}
	return nil
}

// IsPrimitiveType determine whether the type name is a primitive type
func IsPrimitiveType(typeName string) bool {
	switch typeName {
	case "string", "number", "integer", "boolean", "array", "object":
		return true
	default:
		return false
	}
}

// IsNumericType determines whether the swagger type name is a numeric type
func IsNumericType(typeName string) bool {
	return typeName == "integer" || typeName == "number"
}

// TransToValidSchemeType indicates type will transfer golang basic type to swagger supported type.
func TransToValidSchemeType(typeName string) string {
	var deArray bool
	if strings.Contains(typeName, "array_") {
		deArray = true
	}

	typeName = DelArray(typeName)
	var resultStr string

	switch typeName {
	case "uint", "int", "uint8", "int8", "uint16", "int16", "byte":
		resultStr = "integer"
	case "uint32", "int32", "rune":
		resultStr = "integer"
	case "uint64", "int64":
		resultStr = "integer"
	case "float32", "float64", "float":
		resultStr = "number"
	case "bool":
		resultStr = "boolean"
	case "string":
		resultStr = "string"
	default:
		resultStr = typeName // to support user defined types
	}
	if deArray {
		resultStr = "array_"
	}
	return resultStr
}

// IsGolangPrimitiveType determine whether the type name is a golang primitive type
func IsGolangPrimitiveType(typeName string) bool {
	switch typeName {
	case "uint",
		"int",
		"uint8",
		"int8",
		"uint16",
		"int16",
		"byte",
		"uint32",
		"int32",
		"rune",
		"uint64",
		"int64",
		"float32",
		"float64",
		"bool",
		"string":
		return true
	default:
		return false
	}
}
