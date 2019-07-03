package replace

import (
	"fmt"
	"log"
	"os"

	"github.com/swaggo/swag"
)

type Replace struct {
}

func New() *Replace {
	return &Replace{}
}

type Config struct {
	// SearchDir the swag would be parse
	SearchDir string

	MainFile string

	Detail bool
}

func (f *Replace) Build(config *Config) error {
	if _, err := os.Stat(config.SearchDir); os.IsNotExist(err) {
		return fmt.Errorf("dir: %s is not exist", config.SearchDir)
	}

	log.Println("Formating code.... ")
	rp := swag.NewReplacer()
	rp.ReplaceDetail = config.Detail
	if err := rp.ReplaceAPI(config.SearchDir, config.MainFile); err != nil {
		return err
	}
	return nil
}
