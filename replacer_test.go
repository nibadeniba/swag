package swag

import (
	"fmt"
	"testing"
)

func TestReplacer_ReplaceGeneralAPIInfo(t *testing.T) {
	replacer := NewReplacer()
	err := replacer.ReplaceAPI("testdata/replacement", "main.go")
	if err != nil {
		fmt.Println(err, "ERR")
	}
}
