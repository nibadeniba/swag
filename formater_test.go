package swag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormater_FormatMainFile(t *testing.T) {
	formater := NewFormater()
	assert.NoError(t, formater.FormatFile("parser.go"))
}
