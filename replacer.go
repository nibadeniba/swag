package swag

import (
	"bytes"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/ioutil"
	"path"
	"strings"
	"text/template"

	"github.com/pkg/errors"
)

const (
	generalTemplateD = `
// @title            {{.Title}}
//// API的版本号
// @version          v1.0
// @desc      此处可写一些 API 的相关说明
//// 调试接口时的本地地址，可以写多个，逗号分隔
// @host             192.168.5.6:8080,api.dlab.com
//// 公共的 URL ，比如： api.dlab.com/bms
// @basePath         /
// -------- Module --------
//// 项目模块的模块名
// @tag.name    日志模块
// @tag.name    订单模块
// @tag.name    物流模块
// ------- Security -------
// @securityDef.apikey      JWT_Token
// @in      header
// @name    Authorization`

	generalTemplate = `
// @title       {{.Title}}
// @version     v1.0
// @desc        此处可写一些 API 的相关说明
// @host        192.168.5.6:8080,api.dlab.com
// @basePath    /
// -------- Module --------
// @tag.name    日志模块
// @tag.name    订单模块
// @tag.name    物流模块
// ------- Security -------
// @securityDef.apikey     JWT_Token
// @in      header
// @name    Authorization`

	generalRouteTemplate = `
// @title     {{.Title}}
// @desc      接口描述
// @Tags      模块
// @Router    /simple/url    [GET]
`
	generalRouteTemplateD = `
// @title     {{.Title}}
// @desc      接口描述
// @Tags      模块
// @Router    /simple/url    [GET]
// @Accept     form
// @Param      resource_id        int            form   资源ID
// @Success    {object}           bll.CModel     返回值
// @Fail       400                [1031]         可定义自己的状态码
// @Fail       500                也可不定义，只做解释
// @Security   JWT_Token
`
)

type Replacer struct {
	parser *Parser

	// Replace 的时候是否加上帮助信息
	ReplaceDetail bool
}

func NewReplacer() *Replacer {
	replacer := &Replacer{
		parser: New(),
	}
	return replacer
}

func (replacer *Replacer) ReplaceAPI(searchDir string, mainAPIFile string) error {
	Println(" Replace API ...")
	if err := replacer.parser.getAllGoFileInfo(searchDir); err != nil {
		return err
	}

	// Main file
	if err := replacer.ReplaceAPIInfo(path.Join(searchDir, mainAPIFile), true, nil); err != nil {
		return err
	}

	// Route file
	for fileName, astFile := range replacer.parser.files {
		if err := replacer.ReplaceAPIInfo(fileName, false, astFile); err != nil {
			return err
		}
	}
	return nil
}

func (replacer *Replacer) ReplaceAPIInfo(fileP string, isMain bool, astFile *ast.File) error {
	if astFile == nil {
		fileSet := token.NewFileSet()
		fileTree, err := goparser.ParseFile(fileSet, fileP, nil, goparser.ParseComments)
		if err != nil {
			return errors.Wrap(err, "cannot parse source files")
		}
		astFile = fileTree
	}

	// Read file
	srcBytes, err := ioutil.ReadFile(fileP)
	src := string(srcBytes)
	if err != nil {
		return errors.Wrap(err, "cannot open files,path :"+fileP)
	}

	if astFile.Comments != nil {
		for _, comment := range astFile.Comments {
			comments := strings.Split(comment.Text(), "\n")
			for _, commentLine := range comments {
				attribute := strings.ToLower(strings.Split(commentLine, " ")[0])
				switch attribute {
				case "@#":
					tempBuffer := bytes.Buffer{}
					oldString := commentLine
					title := strings.TrimSpace(commentLine[len(attribute):])
					gTemplate := ""
					if replacer.ReplaceDetail {
						if isMain {
							gTemplate = generalTemplateD
						} else {
							gTemplate = generalRouteTemplateD
						}
					} else {
						if isMain {
							gTemplate = generalTemplate

						} else {
							gTemplate = generalRouteTemplate
						}
					}

					t := template.Must(template.New("temp").Parse(gTemplate))
					err := t.Execute(&tempBuffer, &struct {
						Title string
					}{Title: title})
					if err != nil {
						return errors.Wrap(err, "cannot parse soure files")
					}

					// Replace old
					r := tempBuffer.String()
					if len(oldString) != 0 {
						src = strings.ReplaceAll(src, oldString, r)
					}
				}
			}
		}
	}

	return WriteBack(fileP, []byte(src), srcBytes)
}
