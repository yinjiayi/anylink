package admin

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/bjdgyc/anylink/dbdata"
	"github.com/gorilla/mux"
)

func registerGroupSSORoutes(r *mux.Router) {
	// These routes inherit the same administrator authentication middleware as
	// the existing group editor and are not on its unauthenticated allowlist.
	r.HandleFunc("/group/sso", GroupSSODetail).Methods(http.MethodGet)
	r.HandleFunc("/group/sso/set", GroupSSOSet).Methods(http.MethodPost)
}

func GroupSSODetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil || id <= 0 {
		RespError(w, RespParamErr, dbdata.ErrSSOGroupID)
		return
	}
	info, err := dbdata.GetGroupSSO(id)
	if err != nil {
		groupSSOError(w, err)
		return
	}
	RespSucess(w, info)
}

func GroupSSOSet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		RespError(w, RespParamErr, "sso_content_type_required")
		return
	}
	var update dbdata.GroupSSOUpdate
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&update); err != nil {
		RespError(w, RespParamErr, "sso_request_invalid")
		return
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		RespError(w, RespParamErr, "sso_request_invalid")
		return
	}
	info, err := dbdata.SetGroupSSO(update)
	if err != nil {
		groupSSOError(w, err)
		return
	}
	RespSucess(w, info)
}

func groupSSOError(w http.ResponseWriter, err error) {
	for _, expected := range []error{
		dbdata.ErrSSOGroupID, dbdata.ErrSSOGroupNotFound, dbdata.ErrSSOConfigConflict,
		dbdata.ErrSSORevision, dbdata.ErrSSOConfigInvalid, dbdata.ErrSSOStoredConfig,
		dbdata.ErrSSOProviderChange, dbdata.ErrSSOSecretAction, dbdata.ErrSSOSecretRequired,
		dbdata.ErrSSOSecretNotEmpty,
	} {
		if errors.Is(err, expected) {
			RespError(w, RespParamErr, err.Error())
			return
		}
	}
	// Database driver errors can include SQL arguments, including client_secret.
	RespError(w, RespInternalErr, "sso_database_error")
}
