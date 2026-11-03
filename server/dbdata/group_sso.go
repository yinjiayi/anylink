package dbdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/bjdgyc/anylink/pkg/sso"
	"xorm.io/xorm"
)

var (
	ErrGroupWrite        = errors.New("group_database_error")
	ErrSSOGroupID        = errors.New("sso_group_id_invalid")
	ErrSSOGroupNotFound  = errors.New("sso_group_not_found")
	ErrSSOConfigConflict = errors.New("sso_config_conflict")
	ErrSSORevision       = errors.New("sso_revision_required")
	ErrSSOConfigInvalid  = errors.New("sso_config_invalid")
	ErrSSOStoredConfig   = errors.New("sso_stored_config_invalid")
	ErrSSOProviderChange = errors.New("sso_provider_changed_secret_action_required")
	ErrSSOSecretAction   = errors.New("sso_secret_action_invalid")
	ErrSSOSecretRequired = errors.New("sso_secret_required")
	ErrSSOSecretNotEmpty = errors.New("sso_secret_must_be_empty")
)

// GroupSSOInfo is the dedicated administration view. A secret is never returned,
// including immediately after it has been changed.
type GroupSSOInfo struct {
	ID        int         `json:"id"`
	Name      string      `json:"name"`
	Status    int8        `json:"status"`
	AuthType  string      `json:"auth_type"`
	Config    *sso.Config `json:"config"`
	SecretSet bool        `json:"secret_set"`
	Revision  string      `json:"revision"`
}

type GroupSSOUpdate struct {
	ID           int        `json:"id"`
	Config       sso.Config `json:"config"`
	Revision     string     `json:"revision"`
	SecretAction string     `json:"secret_action"`
}

// Preserve the raw database representation for an atomic compare-and-swap.
// Re-marshalling a map would not preserve older JSON whitespace or key order.
type groupSSORow struct {
	ID     int     `xorm:"id"`
	Name   string  `xorm:"name"`
	Status int8    `xorm:"status"`
	Auth   *string `xorm:"auth"`
}

func (g groupSSORow) revision() string {
	raw := "null"
	if g.Auth != nil {
		raw = *g.Auth
	}
	digest := sha256.Sum256([]byte(strconv.Itoa(g.ID) + ":" + raw))
	return hex.EncodeToString(digest[:])
}

func (g groupSSORow) info() (*GroupSSOInfo, error) {
	info := &GroupSSOInfo{ID: g.ID, Name: g.Name, Status: g.Status, AuthType: "local", Revision: g.revision()}
	if g.Auth == nil || *g.Auth == "" {
		return info, nil
	}
	var auth map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*g.Auth), &auth); err != nil {
		return nil, ErrSSOStoredConfig
	}
	if rawType, ok := auth["type"]; ok {
		if err := json.Unmarshal(rawType, &info.AuthType); err != nil {
			return nil, ErrSSOStoredConfig
		}
	}
	if info.AuthType != "oidc" && info.AuthType != "oauth2" {
		return info, nil
	}
	var config sso.Config
	if err := json.Unmarshal(auth[info.AuthType], &config); err != nil {
		return nil, ErrSSOStoredConfig
	}
	// Do not validate the stored configuration here: administrators must be able
	// to read and repair a configuration rejected by a newer validation rule.
	config.Type = info.AuthType
	info.SecretSet = config.ClientSecret != ""
	config.ClientSecret = ""
	info.Config = &config
	return info, nil
}

func readGroupSSORow(id int) (groupSSORow, error) {
	var row groupSSORow
	if id <= 0 {
		return row, ErrSSOGroupID
	}
	has, err := xdb.Table(new(Group)).Where("id = ?", id).Get(&row)
	if err != nil {
		return row, err
	}
	if !has {
		return row, ErrSSOGroupNotFound
	}
	return row, nil
}

func GetGroupSSO(id int) (*GroupSSOInfo, error) {
	row, err := readGroupSSORow(id)
	if err != nil {
		return nil, err
	}
	return row.info()
}

// PrepareGroupForAdmin keeps legacy group detail/list responses consistent with
// the dedicated editor. The revision and redacted Auth come from the same row.
func PrepareGroupForAdmin(group *Group) error {
	row, err := readGroupSSORow(group.Id)
	if err != nil {
		return err
	}
	info, err := row.info()
	if err != nil {
		return err
	}
	group.AuthRevision = info.Revision
	group.SSOSecretSet = info.SecretSet
	group.SSOSecretAction = "preserve"
	group.Auth = map[string]interface{}{"type": "local"}
	if row.Auth != nil && *row.Auth != "" && *row.Auth != "null" {
		if err := json.Unmarshal([]byte(*row.Auth), &group.Auth); err != nil {
			return ErrSSOStoredConfig
		}
	}
	if len(group.Auth) == 0 {
		group.Auth = map[string]interface{}{"type": "local"}
	}
	// Also scrub inactive SSO entries in legacy data left by older editors.
	for _, typ := range []string{"oidc", "oauth2"} {
		if nested, ok := group.Auth[typ].(map[string]interface{}); ok {
			nested["client_secret"] = ""
		}
	}
	return nil
}

// SetGroupFromAdmin applies the same secret and revision rules to the original
// all-fields editor, preventing it from bypassing the dedicated SSO endpoint.
// Internal initialization and maintenance callers continue to use SetGroup.
func SetGroupFromAdmin(group *Group) error {
	var guard *groupSSORow
	current := &GroupSSOInfo{}
	if group.Id > 0 {
		row, err := readGroupSSORow(group.Id)
		if err != nil {
			return err
		}
		if group.AuthRevision == "" {
			return ErrSSORevision
		}
		if group.AuthRevision != row.revision() {
			return ErrSSOConfigConflict
		}
		current, err = row.info()
		if err != nil {
			return err
		}
		guard = &row
	}
	typ, _ := group.Auth["type"].(string)
	if typ == "oidc" || typ == "oauth2" {
		config, err := SSOConfig(group.Auth)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrSSOConfigInvalid, err)
		}
		row := groupSSORow{}
		if guard != nil {
			row = *guard
		}
		config, err = mergeGroupSSOSecret(row, current, config, group.SSOSecretAction)
		if err != nil {
			return err
		}
		group.Auth = map[string]interface{}{"type": typ, typ: config}
	}
	return setGroup(group, guard)
}

// SetGroupSSO only changes the group's authentication column. In particular, a
// stale SSO page cannot overwrite routing, DNS, ACL or enablement edits.
func SetGroupSSO(update GroupSSOUpdate) (*GroupSSOInfo, error) {
	row, err := readGroupSSORow(update.ID)
	if err != nil {
		return nil, err
	}
	if update.Revision == "" {
		return nil, ErrSSORevision
	}
	if update.Revision != row.revision() {
		return nil, ErrSSOConfigConflict
	}
	current, err := row.info()
	if err != nil {
		return nil, err
	}
	config, err := mergeGroupSSOSecret(row, current, update.Config, update.SecretAction)
	if err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSSOConfigInvalid, err)
	}
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) > 65536 {
		return nil, fmt.Errorf("%w: configuration exceeds 65536 bytes", ErrSSOConfigInvalid)
	}
	auth := map[string]interface{}{"type": config.Type, config.Type: config}
	session := xdb.ID(update.ID).Cols("auth")
	defer session.Close()
	applyGroupAuthGuard(session, row)
	changed, err := session.Update(&Group{Auth: auth})
	if err := checkGroupAuthUpdate(changed, err, row, auth); err != nil {
		return nil, err
	}
	return GetGroupSSO(update.ID)
}

func mergeGroupSSOSecret(row groupSSORow, current *GroupSSOInfo, config sso.Config, action string) (sso.Config, error) {
	switch action {
	case "", "preserve":
		if config.ClientSecret != "" {
			return config, ErrSSOSecretNotEmpty
		}
		if current.SecretSet {
			if !sameSSOProvider(*current.Config, config) {
				return config, ErrSSOProviderChange
			}
			var auth map[string]json.RawMessage
			var stored sso.Config
			// row.info already checked these exact JSON representations.
			_ = json.Unmarshal([]byte(*row.Auth), &auth)
			_ = json.Unmarshal(auth[current.AuthType], &stored)
			config.ClientSecret = stored.ClientSecret
		}
	case "replace":
		if config.ClientSecret == "" {
			return config, ErrSSOSecretRequired
		}
	case "clear":
		if config.ClientSecret != "" {
			return config, ErrSSOSecretNotEmpty
		}
	default:
		return config, ErrSSOSecretAction
	}
	return config, nil
}

func applyGroupAuthGuard(session *xorm.Session, row groupSSORow) {
	if row.Auth == nil {
		session.Where("auth IS NULL")
	} else {
		// Binary comparison matters on case-insensitive MySQL/SQL Server
		// collations: a concurrent issuer or subject change must not be lost.
		switch xdb.DriverName() {
		case "mysql":
			session.Where("BINARY auth = ?", *row.Auth)
		case "mssql", "sqlserver":
			session.Where("CAST(auth AS NVARCHAR(MAX)) COLLATE Latin1_General_100_BIN2 = ?", *row.Auth)
		default:
			session.Where("auth = ?", *row.Auth)
		}
	}
}

func checkGroupAuthUpdate(changed int64, err error, row groupSSORow, auth map[string]interface{}) error {
	if err != nil {
		return err
	}
	if changed == 1 {
		return nil
	}
	// MySQL reports zero changed rows for an unchanged write unless its DSN
	// enables clientFoundRows. Only accept that case if Auth was already exactly
	// the desired value and remains unchanged; a failed CAS is still a conflict.
	encoded, encodeErr := json.Marshal(auth)
	if changed == 0 && encodeErr == nil && row.Auth != nil && string(encoded) == *row.Auth {
		current, readErr := readGroupSSORow(row.ID)
		if readErr == nil && current.revision() == row.revision() {
			return nil
		}
	}
	return ErrSSOConfigConflict
}

func sameSSOProvider(previous, next sso.Config) bool {
	if previous.Type != next.Type || previous.ClientID != next.ClientID {
		return false
	}
	if next.Type == "oidc" {
		return previous.Issuer == next.Issuer
	}
	return previous.AuthorizationURL == next.AuthorizationURL && previous.TokenURL == next.TokenURL && previous.UserInfoURL == next.UserInfoURL
}
