package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strings"
)

const (
	EC_G    = "http://ec.doc.dlab.com/json/group.json"
	CMS_G   = "http://c.doc.dlab.com/json/group.json"
	DIRFT_G = "http://drift.doc.dlab.com/json/group.json"
	APP_G   = "http://app.doc.dlab.com/json/group.json"
)

type Push struct {
}

func New() *Push {
	return &Push{}
}

type Config struct {
	Dir    string
	System string
}

type GroupJson struct {
	Name           string `json:"name"`
	SwaggerVersion string `json:"swaggerVersion"`
	Url            string `json:"url"`
	Location       string `json:"location"`
}

func (f *Push) Build(config *Config) error {
	systems := strings.Split(config.System, ".")
	if len(config.System) < 2 {
		return fmt.Errorf("参数不合法: config system %s", config.System)
	}

	system := systems[0]
	module := systems[1]

	path := system + "_doc"
	println(" 正在上传文件 " + module)

	cmd := exec.Command("scp", config.Dir+"/swagger.json",
		"root@192.168.4.31:/root/"+path+"/"+module+".json")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		println(err.Error(), "++", stderr.String())
		return err
	}

	var urlF string
	if system == "ec" {
		urlF = EC_G
	} else if system == "cms" {
		urlF = CMS_G
	} else if system == "drift" {
		urlF = DIRFT_G
	} else if system == "app" {
		urlF = APP_G
	}

	resp, err := http.Get(urlF)
	if err != nil {
		return err
	}

	b, _ := ioutil.ReadAll(resp.Body)

	// Group.json
	gJson := make([]GroupJson, 0)
	err = json.Unmarshal(b, &gJson)
	if err != nil {
		return err
	}

	for _, e := range gJson {
		if e.Name == module {
			// 有就不管
			return nil
		}
	}

	//新增
	g := &GroupJson{
		Name:           module,
		SwaggerVersion: "2.0",
		Url:            "/json/" + module + ".json",
		Location:       "/json/" + module + ".json",
	}
	gJson = append(gJson, *g)

	gText, err := json.Marshal(&gJson)
	if err != nil {
		return err
	}

	gFile, err := ioutil.TempFile("", "*")
	if err != nil {
		return err
	}

	gFile.Write(gText)
	gFile.Close()

	println(" 正在上传Group文件 " + gFile.Name())

	cmd = exec.Command("scp",
		gFile.Name(),
		"root@192.168.4.31:/root/"+path+"/"+"group.json")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		println(err.Error(), "++", stderr.String())
		return err
	}
	return nil
}
