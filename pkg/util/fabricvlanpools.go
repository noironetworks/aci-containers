package util

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func ParseVlanList(specVlans []string) (vlans []int, vlanBlks []string, combinedStr string, err error) {
	return parseVlanSpecs(specVlans, false)
}
func ParseVlanListWithRangePreserved(specVlans []string) (vlans []int, vlanBlks []string, combinedStr string, err error) {
	return parseVlanSpecs(specVlans, true)
}
func parseVlanSpecs(specVlans []string, preserveRange bool) (vlans []int, vlanBlks []string, combinedStr string, err error) {
	vlanMap := make(map[int]int)
	rangeIdx := -1
	for _, vlan := range specVlans {
		listContents := vlan
		_, after, found := strings.Cut(vlan, "[")
		if found {
			listContents, _, found = strings.Cut(after, "]")
			if !found {
				if err == nil {
					err = fmt.Errorf("failed to parse vlan list: Mismatched brackets: %s", vlan)
				}
				continue
			}
		}
		vlanElems := strings.Split(listContents, ",")
		for idx := range vlanElems {
			vlanStr := strings.TrimSpace(vlanElems[idx])
			rangeIdx++
			if strings.Contains(vlanStr, "-") {
				rangeErr := fmt.Errorf("failed to parse vlan list: vlan range unformed: %s[%s]", vlan, vlanStr)
				vlanRange := strings.Split(vlanStr, "-")
				if len(vlanRange) != 2 {
					if err == nil {
						err = rangeErr
					}
					continue
				}
				vlanFrom, errFrom := strconv.Atoi(vlanRange[0])
				vlanTo, errTo := strconv.Atoi(vlanRange[1])
				if errFrom != nil || errTo != nil {
					if err == nil {
						err = rangeErr
					}
					continue
				}
				if (vlanFrom > vlanTo) || (vlanTo > 4095) || (vlanFrom == 0) || (vlanTo == 0) {
					if err == nil {
						err = rangeErr
					}
					continue
				}
				for i := vlanFrom; i <= vlanTo; i++ {
					if _, ok := vlanMap[i]; !ok {
						vlans = append(vlans, i)
						vlanMap[i] = rangeIdx
					}
				}
			} else {
				vlan, err2 := strconv.Atoi(vlanStr)
				if (err2 != nil) || (vlan > 4095) {
					if err == nil && (vlanStr != "") {
						err = fmt.Errorf("failed to parse vlan list: vlan incorrect: %d[%s]", vlan, vlanStr)
					}
					continue
				}
				if vlan == 0 {
					continue
				}
				if _, ok := vlanMap[vlan]; !ok {
					vlans = append(vlans, vlan)
					vlanMap[vlan] = rangeIdx
				}
			}
		}
	}
	sort.Ints(vlans)
	prev := -2
	rngStart := -1
	rngEnd := -2
	appendToCombinedStr := func() {
		if combinedStr == "" {
			combinedStr += "["
		} else {
			combinedStr += ","
		}
		rngStr := fmt.Sprintf("%d-%d", rngStart, rngEnd)
		combinedStr += rngStr
		vlanBlks = append(vlanBlks, rngStr)
	}
	for _, i := range vlans {
		if prev != i-1 || (preserveRange && (vlanMap[i] != vlanMap[prev])) {
			if rngStart <= rngEnd {
				appendToCombinedStr()
			}
			rngEnd = i
			rngStart = i
		} else {
			rngEnd = i
		}
		prev = i
	}
	if rngStart <= rngEnd {
		appendToCombinedStr()
	}
	if len(combinedStr) != 0 {
		combinedStr += "]"
	}
	return vlans, vlanBlks, combinedStr, err
}

func CombineVlanPoolMaps(nsVlanPoolMap map[string]map[string]string, namespace string) (combinedStr string) {
	combineNsVlanList := func(ns string) string {
		for _, vlanStr := range nsVlanPoolMap[ns] {
			if len(vlanStr) == 0 {
				continue
			}
			var postOpenBrace string
			preCloseBrace := vlanStr
			_, postOpenBrace, found := strings.Cut(vlanStr, "[")
			if found {
				preCloseBrace, _, _ = strings.Cut(postOpenBrace, "]")
			}
			if len(combinedStr) == 0 {
				combinedStr = preCloseBrace
				continue
			}
			combinedStr += "," + preCloseBrace
		}
		return combinedStr
	}
	if namespace == "" {
		for ns := range nsVlanPoolMap {
			combineNsVlanList(ns)
		}
		return combinedStr
	}
	return combineNsVlanList(namespace)
}
