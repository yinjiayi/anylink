// Shared defaults and validation for both the group editor and the dedicated SSO page.
export function ssoDefaults(type) {
  return {
    issuer: '',
    client_id: '',
    client_secret: '',
    public_url: '',
    scopes: type === 'oidc' ? ['openid', 'profile'] : [],
    authorization_url: '',
    token_url: '',
    userinfo_url: '',
    subject_claim: type === 'oauth2' ? 'id' : '',
    browser_mode: 'auto',
    subject_users: {},
  };
}

export function cloneSSOConfig(type, value) {
  return Object.assign(ssoDefaults(type), JSON.parse(JSON.stringify(value || {})));
}

export function parseSubjectUsers(text) {
  const mappings = JSON.parse(text);
  if (mappings === null || Array.isArray(mappings) || typeof mappings !== 'object' ||
      Object.keys(mappings).some(subject => !validIdentity(subject) ||
        !validIdentity(mappings[subject]))) {
    throw new Error('用户身份映射必须是 JSON 对象，每个 subject 对应一个非空 AnyLink 用户名，且不能包含首尾空白或控制字符。');
  }
  return mappings;
}

function validIdentity(value) {
  return typeof value === 'string' && value !== '' && value === value.trim() &&
    !Array.from(value).some(character => {
      const code = character.charCodeAt(0);
      return code < 32 || (code >= 127 && code <= 159);
    });
}

function isHTTPSURL(value) {
  try {
    const parsed = new URL(value);
    return typeof value === 'string' && value === value.trim() &&
      parsed.protocol === 'https:' && !!parsed.hostname &&
      !parsed.username && !parsed.password && !value.includes('#');
  } catch (error) {
    return false;
  }
}

// Return field errors rather than showing global messages so callers can place
// this component inside an existing form without registering nested form items.
export function normalizeSSOConfig(type, value, scopesText, subjectUsersText) {
  const config = cloneSSOConfig(type, value);
  const errors = {};
  if (!['oidc', 'oauth2'].includes(type)) {
    errors.type = '请选择 OIDC 或 OAuth2 认证方式。';
  }
  if (typeof config.client_id !== 'string' || !config.client_id.trim()) {
    errors.client_id = '请输入 Client ID。';
  }
  if (typeof config.public_url === 'string') {
    config.public_url = config.public_url.replace(/\/$/, '');
  }
  if (!isHTTPSURL(config.public_url)) {
    errors.public_url = '请输入有效 HTTPS 地址，不含用户名、密码或片段。';
  } else {
    const parsed = new URL(config.public_url);
    // URL normalizes an origin to pathname "/" and collapses dot segments.
    // Also inspect the original form so an explicit path cannot be hidden by
    // that normalization (e.g. /., /foo/.., or an extra trailing slash).
    if (parsed.pathname !== '/' || !/^https:\/\/[^/?#\\]+$/.test(config.public_url)) {
      errors.public_url = 'VPN 外部地址只填写域名和可选端口，不含路径或查询参数。';
    }
  }
  if (type === 'oidc') {
    // OIDC always maps the verified sub. Repair legacy values of this hidden
    // field so administrators can correct old configurations through the UI.
    config.subject_claim = 'sub';
    if (!isHTTPSURL(config.issuer) || config.issuer.includes('?')) {
      errors.issuer = '请输入有效 HTTPS Issuer，不含查询参数或片段。';
    }
  } else if (type === 'oauth2') {
    ['authorization_url', 'token_url', 'userinfo_url'].forEach(field => {
      if (!isHTTPSURL(config[field])) {
        errors[field] = '请输入有效 HTTPS 地址，不含用户名、密码或片段。';
      }
    });
    if (!validIdentity(config.subject_claim) || ['.', '[', ']'].some(character => config.subject_claim.includes(character))) {
      errors.subject_claim = '请输入 userinfo JSON 顶层的稳定身份字段，如 id。';
    }
  }
  const scopes = scopesText.trim().split(/\s+/).filter(Boolean);
  config.scopes = Array.from(new Set(scopes));
  if (type === 'oidc' && !config.scopes.includes('openid')) {
    errors.scopes = 'OIDC Scopes 必须包含 openid。';
  }
  if (!['auto', 'internal', 'external'].includes(config.browser_mode)) {
    errors.browser_mode = '请选择自动协商、内置浏览器或系统浏览器。';
  }
  try {
    config.subject_users = parseSubjectUsers(subjectUsersText);
  } catch (error) {
    errors.subject_users = '请输入合法 JSON 对象，每个 subject 对应一个非空 AnyLink 用户名，且不能包含首尾空白或控制字符。';
  }
  return { config, errors };
}
