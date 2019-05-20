package swag

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFormater_FormatMainFile(t *testing.T) {
	formater := NewFormater()
	assert.NoError(t, formater.FormatAPI("testdata/daddylab"))
}
