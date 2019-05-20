package format

import (
	"fmt"
	"github.com/swaggo/swag"
	"log"
	"os"
)

type Fmt struct {
}

func New() *Fmt {
	return &Fmt{}
}

type Config struct {
	// SearchDir the swag would be parse
	SearchDir string
}

func (f *Fmt) Build(config *Config) error {
	if _, err := os.Stat(config.SearchDir); os.IsNotExist(err) {
		return fmt.Errorf("dir: %s is not exist", config.SearchDir)
	}

	log.Println("Formating code.... ")
	formater := swag.NewFormater()
	if err := formater.FormatAPI(config.SearchDir); err != nil {
		return err
	}
	return nil
}
