package util

import (
	"fmt"
	"strconv"
	"strings"
)

func ParseVlanList(specVlans []string) (vlans []int, vlanBlks []string, combinedStr string, err error) {
	vlanMap := make(map[int]bool)
	for _, vlan := range specVlans {
		listContents := vlan
		_, after, found := strings.Cut(vlan, "[")
		if found {
			listContents, _, found = strings.Cut(after, "]")
			if !found {
				err := fmt.Errorf("Failed to parse vlan list: Mismatched brackets: %s", vlan)
				return vlans, vlanBlks, combinedStr, err
			}
		}
		vlanElems := strings.Split(listContents, ",")
		for idx := range vlanElems {
			vlanAdded := false
			vlanStr := strings.TrimSpace(vlanElems[idx])
			if strings.Contains(vlanStr, "-") {
				rangeErr := fmt.Errorf("Failed to parse vlan list: vlan range unformed: %s[%s]", vlan, vlanStr)
				vlanRange := strings.Split(vlanStr, "-")
				if len(vlanRange) != 2 {
					return vlans, vlanBlks, combinedStr, rangeErr
				}
				vlanFrom, errFrom := strconv.Atoi(vlanRange[0])
				vlanTo, errTo := strconv.Atoi(vlanRange[1])
				if errFrom != nil || errTo != nil {
					return vlans, vlanBlks, combinedStr, rangeErr
				}
				if vlanFrom > vlanTo || vlanTo > 4095 {
					return vlans, vlanBlks, combinedStr, rangeErr
				}
				overlap := false
				for i := vlanFrom; i <= vlanTo; i++ {
					if _, ok := vlanMap[i]; !ok {
						vlans = append(vlans, i)
						vlanMap[i] = true
					} else {
						overlap = true
					}
				}
				vlanAdded = !overlap
			} else {
				vlan, err := strconv.Atoi(vlanStr)
				if err != nil || vlan > 4095 {
					err := fmt.Errorf("Failed to parse vlan list: vlan incorrect: %d[%s]", vlan, vlanStr)
					return vlans, vlanBlks, combinedStr, err
				}
				if _, ok := vlanMap[vlan]; !ok {
					vlans = append(vlans, vlan)
					vlanMap[vlan] = true
					vlanAdded = true
				}
			}
			if vlanAdded {
				vlanBlks = append(vlanBlks, vlanStr)
				if len(combinedStr) == 0 {
					combinedStr = "[" + vlanStr
					continue
				}
				combinedStr += "," + vlanStr
			}
		}
	}
	if len(combinedStr) != 0 {
		combinedStr += "]"
	}
	return vlans, vlanBlks, combinedStr, err
}
