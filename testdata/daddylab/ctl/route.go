package ctl

// ForRoute
func Route() {
	// @Summary       Show a account
	// @Description   测试的 1
	// @ID            get-string-by-incc
	// @Accept        json
	// @Produce       json
	// @Param         some_id          path       string   true   "Some ID"
	// @Param         category         query      int      true   "Category"   Enums(1, 2, 3)
	// @Param         offset           query      int      true   "Offset"     Mininum(0) default(0)
	// @Param         limit            query      int      true   "Limit"      Maxinum(50) default(10)
	// @Param         q                query      string   true   "q"          Minlength(1) Maxlength(50) default("")
	// @Success       200              {string}   string   "ok"
	// @Router        /accounts/{id}   [get]
	route.Handler()

	// @Summary       Show a account2
	// @Description   测试的 2
	// @ID            get-string-by-indd
	// @Accept        json
	// @Produce       json
	// @Param         file              formData   file     true   "this is a test file"
	// @Success       200               {string}   string   "ok"
	// @Router        /accounts2/{id}   [post]
	route.Handler()
}

func Route2() {
	// @Summary       Show a account3
	// @Description   测试的 3
	// @ID            get-string-by-inww
	// @Accept        json
	// @Produce       json
	// @Param         some_id          path       string   true   "Some ID"
	// @Param         category         query      int      true   "Category"   Enums(1, 2, 3)
	// @Param         offset           query      int      true   "Offset"     Mininum(0) default(0)
	// @Param         limit            query      int      true   "Limit"      Maxinum(50) default(10)
	// @Param         q                query      string   true   "q"          Minlength(1) Maxlength(50) default("")
	// @Success       200              {string}   string   "ok"
	// @Router        /accounts/{id}   [get]
	route.Handler()

	// @Summary       Show a account4
	// @Description   测试的 4
	// @ID            get-eefa
	// @Accept        json
	// @Produce       json
	// @Param         file              formData   file     true   "this is a test file"
	// @Success       200               {string}   string   "ok"
	// @Router        /accounts2/{id}   [post]
	route.Handler()
}
