package api

import (
	"github.com/gin-gonic/gin"
	"github.com/swaggo/swag/example/basic/web"
)

// GetStringByInt example
// @Title     Add a new pet to the store
// @Desc      get string by ID
// @ID        get-string-by-int
// @Router    /testapi/get-string-by-int/{some_id}   [POST]
// @Accept    json
// @Produce   json
// @Param     pet          struct         body   传入Json格式的字段
// @Param     -id          int            它的ID
// @Param     -category    struct         仓库
// @Param     --id         int            仓库id
// @Param     --name       string         仓库名称
// @Param     -name        string         它的名称
// @Param     -photoUrls   array_string   format(url)   图片
// @Param     -tags        struct         标签
// @Param     --id         int            标签ID
// @Param     --name       string         标签名
// @Param     -status      string         状态
// @Param     -
// @Single    string   ok
// @Fail      400      [1006]   "We need ID!!"
// @Fail      404      "Can not find ID"
func GetStringByInt(c *gin.Context) {
	_ := web.Pet{}
	//write your code
}

// GetStructArrayByString example
// @Title     get a new pet to the store
// @Desc      get struct array by ID
// @ID        get-struct-array-by-string
// @Router    /testapi/get-struct-array-by-string/{some_id}   [get]
// @Accept    json
// @Produce   json
// @Param     some_id    path      string   true   Some ID
// @Param     offset     query     int      true   Offset
// @Param     limit      query     int      true   Offset
// @Success   {object}   web.Pet   资源
// @Fail      400        参数错误
// @Fail      404        [1056]   请登录
func GetStructArrayByString(c *gin.Context) {
	//write your code
}

// Pet3 example
type Pet3 struct {
	ID int `json:"id"`
}
