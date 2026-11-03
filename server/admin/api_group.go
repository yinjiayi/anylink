package admin

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
)

func GroupList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_ = r.ParseForm()
	pageS := r.FormValue("page")
	page, _ := strconv.Atoi(pageS)
	if page < 1 {
		page = 1
	}

	var pageSize = dbdata.PageSize

	count := dbdata.CountAll(&dbdata.Group{})

	var datas []dbdata.Group
	err := dbdata.Find(&datas, pageSize, page)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	for i := range datas {
		if err := dbdata.PrepareGroupForAdmin(&datas[i]); err != nil {
			groupSSOError(w, err)
			return
		}
	}

	data := map[string]interface{}{
		"count":     count,
		"page_size": pageSize,
		"datas":     datas,
	}

	RespSucess(w, data)
}

func GroupNames(w http.ResponseWriter, r *http.Request) {
	var names = dbdata.GetGroupNames()
	data := map[string]interface{}{
		"count":     len(names),
		"page_size": 0,
		"datas":     names,
	}
	RespSucess(w, data)
}

func GroupNamesIds(w http.ResponseWriter, r *http.Request) {
	var names = dbdata.GetGroupNamesIds()
	data := map[string]interface{}{
		"count":     len(names),
		"page_size": 0,
		"datas":     names,
	}
	RespSucess(w, data)
}

func GroupDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_ = r.ParseForm()
	idS := r.FormValue("id")
	id, _ := strconv.Atoi(idS)
	if id < 1 {
		RespError(w, RespParamErr, "Id错误")
		return
	}

	var data dbdata.Group
	err := dbdata.One("Id", id, &data)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	if err := dbdata.PrepareGroupForAdmin(&data); err != nil {
		groupSSOError(w, err)
		return
	}
	// 兼容旧数据
	if data.SplitDns == nil {
		data.SplitDns = []dbdata.ValData{}
	}
	RespSucess(w, data)
}

func GroupSet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		RespError(w, RespParamErr, "sso_content_type_required")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		RespError(w, RespParamErr, "sso_request_invalid")
		return
	}
	defer r.Body.Close()
	v := &dbdata.Group{}
	err = json.Unmarshal(body, v)
	if err != nil {
		RespError(w, RespParamErr, "sso_request_invalid")
		return
	}

	err = dbdata.SetGroupFromAdmin(v)
	if err != nil {
		if errors.Is(err, dbdata.ErrGroupWrite) {
			RespError(w, RespInternalErr, dbdata.ErrGroupWrite.Error())
		} else {
			RespError(w, RespParamErr, err)
		}
		return
	}

	RespSucess(w, nil)
}

func GroupDel(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	idS := r.FormValue("id")
	id, _ := strconv.Atoi(idS)
	if id < 1 {
		RespError(w, RespParamErr, "Id错误")
		return
	}

	data := dbdata.Group{Id: id}
	err := dbdata.Del(&data)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	RespSucess(w, nil)
}

func GroupAuthLogin(w http.ResponseWriter, r *http.Request) {
	type AuthLoginData struct {
		Name string                 `json:"name"`
		Pwd  string                 `json:"pwd"`
		Auth map[string]interface{} `json:"auth"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()
	v := &AuthLoginData{}
	err = json.Unmarshal(body, &v)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	err = dbdata.GroupAuthLogin(v.Name, v.Pwd, v.Auth)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	RespSucess(w, "ok")
}
func SaveLdapUsers(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()

	v := &dbdata.Group{}
	err = json.Unmarshal(body, v)
	if err != nil {
		RespError(w, RespParamErr, "参数错误")
		return
	}

	// 保存LDAP用户
	if v.Auth["type"] == "ldap" {
		authLdap := dbdata.AuthLdap{}
		if err := authLdap.ParseGroup(v); err != nil {
			RespError(w, RespInternalErr, err)
			return
		}
		go func() {
			if err := authLdap.SaveUsers(v); err != nil {
				base.Error("LDAP用户同步失败:", err)
			} else {
				base.Info("LDAP用户同步成功")
			}
		}()
	}
	RespSucess(w, "LDAP用户同步成功")
}
