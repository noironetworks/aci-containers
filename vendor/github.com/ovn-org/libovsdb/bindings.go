package libovsdb

import (
	"fmt"
	"reflect"
)

var (
	intType  = reflect.TypeOf(0)
	realType = reflect.TypeOf(0.0)
	boolType = reflect.TypeOf(true)
	strType  = reflect.TypeOf("")
)

// ErrWrongType describes typing error
type ErrWrongType struct {
	from     string
	expected string
	got      interface{}
}

func (e *ErrWrongType) Error() string {
	return fmt.Sprintf("Wrong Type (%s): expected %s but got %s (%s)",
		e.from, e.expected, e.got, reflect.TypeOf(e.got))
}

// NewErrWrongType creates a new ErrWrongType
func NewErrWrongType(from, expected string, got interface{}) error {
	return &ErrWrongType{
		from:     from,
		expected: expected,
		got:      got,
	}
}

// nativeTypeFromBasic returns the native type that can hold a value of an
// BasicType type
func nativeTypeFromBasic(basicType string) reflect.Type {
	switch basicType {
	case TypeInteger:
		return intType
	case TypeReal:
		return realType
	case TypeBoolean:
		return boolType
	case TypeString:
		return strType
	case TypeUUID:
		return strType
	default:
		panic("Unkown basic type %s basicType")
	}
}

// nativeValueOf returns the native value of the atomic element
// Usually, this is just reflect.ValueOf(elem), with the only exception of the UUID
func nativeValueOf(elem interface{}, elemType ExtendedType) (reflect.Value, error) {
	if elemType == TypeUUID {
		uuid, ok := elem.(UUID)
		if !ok {
			return reflect.ValueOf(nil), NewErrWrongType("nativeValueOf", "UUID", elem)
		}
		return reflect.ValueOf(uuid.GoUUID), nil
	}
	return reflect.ValueOf(elem), nil

}

//nativeType returns the reflect.Type that can hold the value of a column
//OVS Type to Native Type convertions:
// OVS sets -> go slices
// OVS uuid -> go strings
// OVS map  -> go map
// OVS enum -> go native type depending on the type of the enum key
func nativeType(column *ColumnSchema) reflect.Type {
	switch column.Type {
	case TypeInteger, TypeReal, TypeBoolean, TypeUUID, TypeString:
		return nativeTypeFromBasic(column.Type)
	case TypeEnum:
		return nativeTypeFromBasic(column.TypeObj.Key.Type)
	case TypeMap:
		kType := nativeTypeFromBasic(column.TypeObj.Key.Type)
		vType := nativeTypeFromBasic(column.TypeObj.Value.Type)
		return reflect.MapOf(kType, vType)
	case TypeSet:
		kType := nativeTypeFromBasic(column.TypeObj.Key.Type)
		return reflect.SliceOf(kType)
	default:
		panic(fmt.Errorf("unknown extended type %s", column.Type))
	}
}

// OvsToNative transforms an ovs type to native one based on the column type information
func OvsToNative(column *ColumnSchema, ovsElem interface{}) (interface{}, error) {
	naType := nativeType(column)
	switch column.Type {
	case TypeInteger, TypeReal, TypeString, TypeBoolean, TypeEnum:
		if reflect.TypeOf(ovsElem) != naType {
			return nil, NewErrWrongType("OvsToNative", naType.String(), ovsElem)
		}
		// Atomic types should have the same underlying type
		return ovsElem, nil
	case TypeUUID:
		uuid, ok := ovsElem.(UUID)
		if !ok {
			return nil, NewErrWrongType("OvsToNative", "UUID", ovsElem)
		}
		return uuid.GoUUID, nil
	case TypeSet:
		// The inner slice is []interface{}
		// We need to convert it to the real type os slice
		var nativeSet reflect.Value

		// RFC says that for a set of exactly one, an atomic type an be sent
		switch ovsSet := ovsElem.(type) {
		case OvsSet:
			nativeSet = reflect.MakeSlice(naType, 0, len(ovsSet.GoSet))
			for _, v := range ovsSet.GoSet {
				vv, err := nativeValueOf(v, column.TypeObj.Key.Type)
				if err != nil {
					return nil, err
				}
				if vv.Type() != naType.Elem() {
					return nil, NewErrWrongType("OvsToNative", fmt.Sprintf("convertible to %s", naType), ovsElem)
				}
				nativeSet = reflect.Append(nativeSet, vv)
			}

		default:
			nativeSet = reflect.MakeSlice(naType, 0, 1)
			keyType := nativeTypeFromBasic(column.TypeObj.Key.Type)

			vv, err := nativeValueOf(ovsElem, column.TypeObj.Key.Type)
			if err != nil {
				return nil, err
			}

			if !vv.Type().ConvertibleTo(keyType) {
				return nil, NewErrWrongType("OvsToNative", keyType.String(), ovsElem)
			}
			nativeSet = reflect.Append(nativeSet, vv)
		}
		return nativeSet.Interface(), nil

	case TypeMap:
		ovsMap, ok := ovsElem.(OvsMap)
		if !ok {
			return nil, NewErrWrongType("OvsToNative", "OvsMap", ovsElem)
		}
		// The inner slice is map[interface]interface{}
		// We need to convert it to the real type os slice
		nativeMap := reflect.MakeMapWithSize(naType, len(ovsMap.GoMap))
		for k, v := range ovsMap.GoMap {
			kk, err := nativeValueOf(k, column.TypeObj.Key.Type)
			if err != nil {
				return nil, err
			}
			vv, err := nativeValueOf(v, column.TypeObj.Value.Type)
			if err != nil {
				return nil, err
			}
			if vv.Type() != naType.Elem() || kk.Type() != naType.Key() {
				return nil, NewErrWrongType("OvsToNative", fmt.Sprintf("convertible to %s", naType), ovsElem)
			}
			nativeMap.SetMapIndex(kk, vv)
		}
		return nativeMap.Interface(), nil
	default:
		panic(fmt.Sprintf("Unknown Type: %v", column.Type))
	}
}

// NativeToOvs transforms an native type to a ovs type based on the column type information
func NativeToOvs(column *ColumnSchema, rawElem interface{}) (interface{}, error) {
	naType := nativeType(column)

	if t := reflect.TypeOf(rawElem); t != naType {
		return nil, NewErrWrongType("NativeToOvs", naType.String(), rawElem)
	}

	switch column.Type {
	case TypeInteger, TypeReal, TypeString, TypeBoolean, TypeEnum:
		return rawElem, nil
	case TypeUUID:
		return UUID{GoUUID: rawElem.(string)}, nil
	case TypeSet:
		var ovsSet *OvsSet
		if column.TypeObj.Key.Type == TypeUUID {
			var ovsSlice []interface{}
			for _, v := range rawElem.([]string) {
				uuid := UUID{GoUUID: v}
				ovsSlice = append(ovsSlice, uuid)
			}
			ovsSet = &OvsSet{GoSet: ovsSlice}

		} else {
			var err error
			ovsSet, err = NewOvsSet(rawElem)
			if err != nil {
				return nil, err
			}
		}
		return ovsSet, nil
	case TypeMap:
		ovsMap, err := NewOvsMap(rawElem)
		if err != nil {
			return nil, err
		}
		return ovsMap, nil
	default:
		panic(fmt.Sprintf("Unknown Type: %v", column.Type))
	}
}
