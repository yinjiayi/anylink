// Run with: node src/utils/ssoConfig.test.cjs
// The application uses ES modules through Vue CLI; evaluate the standalone
// utility without introducing a second test framework or changing package.json.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const filename = path.join(__dirname, 'ssoConfig.js');
const source = fs.readFileSync(filename, 'utf8').replace(/export function /g, 'function ');
const context = { URL, module: { exports: {} } };
vm.runInNewContext(source + '\nmodule.exports = { ssoDefaults, cloneSSOConfig, parseSubjectUsers, normalizeSSOConfig };', context, { filename });
const { ssoDefaults, cloneSSOConfig, normalizeSSOConfig } = context.module.exports;

function oidc(overrides = {}) {
  return Object.assign(ssoDefaults('oidc'), {
    issuer: 'https://login.example.test/realms/company',
    public_url: 'https://vpn.example.test',
    client_id: 'anylink-vpn',
    subject_users: { subject: 'alice' },
  }, overrides);
}

function validate(config, scopes = 'openid profile', users = '{"subject":"alice"}', type = 'oidc') {
  return normalizeSSOConfig(type, config, scopes, users);
}

for (const origin of ['https://vpn.example.test', 'https://vpn.example.test:8443', 'https://[2001:db8::1]:8443', 'https://vpn.example.test/']) {
  const result = validate(oidc({ public_url: origin }));
  assert.deepStrictEqual(Object.keys(result.errors), [], origin);
  assert.strictEqual(result.config.public_url, origin.replace(/\/$/, ''));
}

for (const origin of [
  'http://vpn.example.test', 'https://vpn.example.test/path', 'https://vpn.example.test?',
  'https://vpn.example.test?x=1', 'https://vpn.example.test#', 'https://vpn.example.test#fragment',
  'https://user:pass@vpn.example.test', 'https://vpn.example.test/.',
  'https://vpn.example.test/path/..', 'https://vpn.example.test//', '', null,
]) {
  assert.ok(validate(oidc({ public_url: origin })).errors.public_url, String(origin));
}

for (const issuer of ['http://login.example.test', 'https://login.example.test?x=1', 'https://login.example.test#']) {
  assert.ok(validate(oidc({ issuer })).errors.issuer, issuer);
}
assert.ok(validate(oidc({ client_id: ' ' })).errors.client_id);
assert.ok(validate(oidc({ browser_mode: 'guess-user-agent' })).errors.browser_mode);
assert.strictEqual(validate(oidc({ subject_claim: 'id' })).config.subject_claim, 'sub');

for (const users of ['[]', 'null', '"text"', '{"subject":123}', '{"subject":" "}', '{"":"alice"}', '{" subject":"alice"}', '{"subject":"alice\\n"}', 'broken']) {
  assert.ok(validate(oidc(), 'openid profile', users).errors.subject_users, users);
}
assert.deepStrictEqual(Object.keys(validate(oidc(), 'openid profile', '{}').errors), []);
assert.ok(validate(oidc(), 'profile').errors.scopes);
assert.strictEqual(JSON.stringify(validate(oidc(), 'openid profile openid').config.scopes), '["openid","profile"]');

const original = oidc({ future_option: { preserved: true } });
const before = JSON.stringify(original);
const normalized = validate(original);
assert.strictEqual(JSON.stringify(original), before, 'normalization mutated the input');
assert.strictEqual(normalized.config.future_option.preserved, true);
const clone = cloneSSOConfig('oidc', original);
clone.future_option.preserved = false;
assert.strictEqual(original.future_option.preserved, true, 'clone retains nested input references');

const oauth2 = Object.assign(ssoDefaults('oauth2'), {
  public_url: 'https://vpn.example.test',
  client_id: 'vpn',
  authorization_url: 'https://idp.example.test/authorize',
  token_url: 'https://idp.example.test/token',
  userinfo_url: 'https://idp.example.test/user',
  subject_claim: 'id',
});
assert.deepStrictEqual(Object.keys(validate(oauth2, 'read:user', '{"123":"alice"}', 'oauth2').errors), []);
for (const field of ['authorization_url', 'token_url', 'userinfo_url']) {
  assert.ok(validate(Object.assign({}, oauth2, { [field]: 'http://idp.example.test' }), '', '{}', 'oauth2').errors[field]);
}
for (const subject_claim of ['', 'profile.id', 'user[0]', ' id ']) {
  assert.ok(validate(Object.assign({}, oauth2, { subject_claim }), '', '{}', 'oauth2').errors.subject_claim);
}

console.log('PASS: SSO config origins, endpoint validation, identity JSON, scopes, and preserved fields');
