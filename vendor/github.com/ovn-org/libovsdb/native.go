package libovsdb

import (
	"fmt"
)

// ErrNoTable describes a error in the provided table information
type ErrNoTable struct {
	table string
}

func (e *ErrNoTable) Error() string {
	return fmt.Sprintf("Table not found: %s", e.table)
}

// NewErrNoTable creates a new ErrNoTable
func NewErrNoTable(table string) error {
	return &ErrNoTable{
		table: table,
	}
}

// NativeAPI is an API that offers functions to interact with libovsdb without
// having to handle it's internal objects. It uses a DatabaseSchema to infer the
// type of each value and make translations.
// OvsMaps are translated to go maps with specific key and values. I.e instead of
//	having to deal with map[interface{}][interface{}], the user will be able to
//	user  map[string] string (or whatever native type can hold the column value)
// OvsSets will be translated to slices
//
// OvsUUID are translated to and from strings
// If the column type is an enum, the native type associated with the underlying enum
// type is used (e.g: string or int)
// Also, type checkings are done. E.g: if you try to put an integer in a column that has
// type string, the API will refuse to create the Ovs object for you
type NativeAPI struct {
	schema *DatabaseSchema
}

// NewNativeAPI returns a NativeAPI
func NewNativeAPI(schema *DatabaseSchema) NativeAPI {
	return NativeAPI{
		schema: schema,
	}
}

// GetRowData transforms a Row to a native type data map[string] interface{}
func (na NativeAPI) GetRowData(tableName string, row *Row) (map[string]interface{}, error) {
	if row == nil {
		return nil, nil
	}
	return na.GetData(tableName, row.Fields)
}

// GetData transforms a map[string]interface{} containing OvS types (e.g: a ResultRow
// has this format) to native.
// The result object must be given as pointer to map[string] interface{}
func (na NativeAPI) GetData(tableName string, ovsData map[string]interface{}) (map[string]interface{}, error) {
	table, ok := na.schema.Tables[tableName]
	if !ok {
		return nil, NewErrNoTable(tableName)
	}
	nativeRow := make(map[string]interface{}, len(table.Columns))

	for name, column := range table.Columns {
		ovsElem, ok := ovsData[name]
		if !ok {
			// Ignore missing columns
			continue
		}
		nativeElem, err := OvsToNative(column, ovsElem)
		if err != nil {
			return nil, fmt.Errorf("table %s, column %s: failed to extract native element: %s", tableName, name, err.Error())
		}
		nativeRow[name] = nativeElem
	}
	return nativeRow, nil
}

// NewRow creates a libovsdb Row from the input data
// data shall not contain libovsdb-specific types (except UUID)
func (na NativeAPI) NewRow(tableName string, data interface{}) (map[string]interface{}, error) {
	table, ok := na.schema.Tables[tableName]
	if !ok {
		return nil, NewErrNoTable(tableName)
	}
	nativeRow, ok := data.(map[string]interface{})
	if !ok {
		return nil, NewErrWrongType("NativeAPI.NewRow", "map[string]interface{}", data)
	}

	ovsRow := make(map[string]interface{}, len(table.Columns))
	for name, column := range table.Columns {
		nativeElem, ok := nativeRow[name]
		if !ok {
			// Ignore missing columns
			continue
		}
		ovsElem, err := NativeToOvs(column, nativeElem)
		if err != nil {
			return nil, fmt.Errorf("table %s, column %s: failed to generate ovs element. %s", tableName, name, err.Error())
		}
		ovsRow[name] = ovsElem
	}
	return ovsRow, nil
}

// NewCondition returns a valid condition to be used inside a Operation
// It accepts native golang types (sets and maps)
// TODO: check condition validity
func (na NativeAPI) NewCondition(tableName, columnName, function string, value interface{}) ([]interface{}, error) {
	column, err := na.schema.GetColumn(tableName, columnName)
	if err != nil {
		return nil, err
	}

	ovsVal, err := NativeToOvs(column, value)
	if err != nil {
		return nil, err
	}
	return []interface{}{columnName, function, ovsVal}, nil
}

// NewMutation returns a valid mutation to be used inside a Operation
// It accepts native golang types (sets and maps)
// TODO: check mutator validity
func (na NativeAPI) NewMutation(tableName, columnName, mutator string, value interface{}) ([]interface{}, error) {
	column, err := na.schema.GetColumn(tableName, columnName)
	if err != nil {
		return nil, err
	}

	ovsVal, err := NativeToOvs(column, value)
	if err != nil {
		return nil, err
	}
	return []interface{}{columnName, mutator, ovsVal}, nil
}
