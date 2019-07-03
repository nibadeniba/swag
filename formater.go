package swag

import (
	"bytes"
	"crypto/md5"
	"fmt"
	goparser "go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/pkg/errors"
)

const SplitTag = "&*"

type Formater struct {
	parser *Parser
}

func NewFormater() *Formater {
	formater := &Formater{
		parser: New(),
	}
	return formater
}

func (formater *Formater) FormatAPI(searchDir string) error {
	Println(" Format API ")

	// format go file
	return filepath.Walk(searchDir, formater.visit)
}

func (formater *Formater) visit(path string, f os.FileInfo, err error) error {
	if err := formater.parser.Skip(path, f); err != nil {
		return err
	}

	if ext := filepath.Ext(path); ext == ".go" {
		err := formater.FormatFile(path)
		if err != nil {
			return fmt.Errorf("ParseFile error:%+v", err)
		}
	}
	return nil
}

func (formater *Formater) FormatFile(filepath string) error {
	fileSet := token.NewFileSet()
	fileTree, err := goparser.ParseFile(fileSet, filepath, nil, goparser.ParseComments)
	if err != nil {
		return errors.Wrap(err, "cannot parse main files,path :"+filepath)
	}
	formatedComments := bytes.Buffer{}
	tabw := NewWriter(&formatedComments, 0, 0, 3, ' ', 0)

	oldCommentsMap := make(map[string]string)

	// Read file
	srcBytes, err := ioutil.ReadFile(filepath)
	src := string(srcBytes)

	if err != nil {
		return errors.Wrap(err, "cannot open main files,path :"+filepath)
	}

	if fileTree.Comments != nil {
		for _, comment := range fileTree.Comments {
			comments := strings.Split(comment.Text(), "\n")
			for _, commentLine := range comments {
				if IsSwagComment(commentLine) || IsBlankComment(commentLine) {
					// If a line has three blank(" "), make it as split char.
					cmd5 := MD5(commentLine)

					reg := regexp.MustCompile(` {3,}`)
					c := reg.ReplaceAllString(commentLine, "\t")
					oldCommentsMap[cmd5] = commentLine

					fmt.Fprintln(tabw, cmd5+SplitTag+c)
				}
			}
		}
		tabw.Flush()
	}

	// Replace old
	newComments := strings.Split(formatedComments.String(), "\n")
	for _, e := range newComments {
		commentSplit := strings.Split(e, SplitTag)
		if len(commentSplit) == 2 {
			commentHash := commentSplit[0]
			commentContent := commentSplit[1]

			if !IsBlankComment(commentContent) {
				oldComment := oldCommentsMap[commentHash]
				if strings.Contains(src, oldComment) {
					src = strings.Replace(src, oldComment, commentContent, 1)
				}
			}
		}
	}
	return WriteBack(filepath, []byte(src), srcBytes)
}

func WriteBack(filepath string, src, old []byte) error {
	// Write back (use golang/gofmt)
	// make a temporary backup before overwriting original
	bakname, err := backupFile(filepath+".", old, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, src, 0644)
	if err != nil {
		os.Rename(bakname, filepath)
		return err
	}
	err = os.Remove(bakname)
	if err != nil {
		return err
	}
	return nil
}

func IsSwagComment(comment string) bool {
	lc := strings.ToLower(comment)
	return regexp.MustCompile("@[A-z]+").MatchString(lc)
}

func IsBlankComment(comment string) bool {
	lc := strings.TrimSpace(comment)
	return len(lc) == 0
}

func MD5(msg string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(msg)))
}

const chmodSupported = runtime.GOOS != "windows"

// backupFile writes data to a new file named filename<number> with permissions perm,
// with <number randomly chosen such that the file name is unique. backupFile returns
// the chosen file name.
func backupFile(filename string, data []byte, perm os.FileMode) (string, error) {
	// create backup file
	f, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return "", err
	}
	bakname := f.Name()
	if chmodSupported {
		err = f.Chmod(perm)
		if err != nil {
			f.Close()
			os.Remove(bakname)
			return bakname, err
		}
	}

	// write data to backup file
	_, err = f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return bakname, err
}
