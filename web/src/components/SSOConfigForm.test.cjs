// Run with: node src/components/SSOConfigForm.test.cjs
// Exercise component state transitions without adding a second frontend runner.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const utilPath = path.join(__dirname, '../utils/ssoConfig.js');
const utilityContext = { URL, module: { exports: {} } };
vm.runInNewContext(fs.readFileSync(utilPath, 'utf8').replace(/export function /g, 'function ') +
  '\nmodule.exports = { ssoDefaults, cloneSSOConfig, parseSubjectUsers, normalizeSSOConfig };', utilityContext);
const utility = utilityContext.module.exports;

function readComponent(filename, imports = {}) {
  const source = fs.readFileSync(filename, 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1]
    .replace(/^import .*$/gm, '').replace('export default', 'module.exports =');
  const context = Object.assign({ URL, console, module: { exports: {} } }, utility, imports);
  vm.runInNewContext(source, context, { filename });
  return context.module.exports;
}

function instantiate(component, props = {}) {
  const instance = Object.assign({}, props);
  Object.assign(instance, component.data.call(instance));
  instance.$set = (object, key, value) => { object[key] = value; };
  instance.$delete = (object, key) => { delete object[key]; };
  instance.$nextTick = () => Promise.resolve();
  instance.$el = { querySelector: () => ({ focus() {} }) };
  for (const [name, method] of Object.entries(component.methods)) instance[name] = method.bind(instance);
  for (const [name, getter] of Object.entries(component.computed || {})) {
    Object.defineProperty(instance, name, { get: getter.bind(instance) });
  }
  return instance;
}

function config() {
  return Object.assign(utility.ssoDefaults('oidc'), {
    issuer: 'https://login.example.test/realms/company',
    client_id: 'vpn-client',
    public_url: 'https://vpn.example.test/',
    subject_users: { subject: 'alice' },
    future_option: { preserved: true },
  });
}

async function run() {
  const component = readComponent(path.join(__dirname, 'SSOConfigForm.vue'));
  const original = config();
  const before = JSON.stringify(original);
  const form = instantiate(component, { type: 'oidc', value: original, secretSet: true });
  const events = [];
  form.$emit = (name, value) => {
    events.push({ name, value });
    if (name === 'input') {
      form.value = value;
      component.watch.value.handler.call(form, value);
    }
  };
  component.created.call(form);
  assert.strictEqual(form.secretPlaceholder, '留空保留已保存密钥');
  assert.strictEqual(form.callbackURL, 'https://vpn.example.test/+CSCOE+/sso/callback');
  form.updateScopes('openid profile ');
  assert.strictEqual(form.scopesText, 'openid profile ', 'v-model echo removed unfinished whitespace');
  const inputCount = events.filter(event => event.name === 'input').length;
  form.updateSubjectUsers('{"unfinished');
  assert.strictEqual(events[events.length - 1].name, 'dirty', 'invalid JSON must still mark the parent dirty');
  assert.strictEqual(events.filter(event => event.name === 'input').length, inputCount);
  form.updateField('client_id', 'updated-client');
  assert.strictEqual(form.subjectUsersText, '{"unfinished', 'other field edits discarded the invalid JSON draft');
  assert.strictEqual(await form.validate(), false);
  assert.ok(form.errors.subject_users);
  form.updateSubjectUsers('{"subject":"bob"}');
  assert.strictEqual(await form.validate(), true);
  assert.strictEqual(form.value.subject_users.subject, 'bob');
  assert.strictEqual(form.value.public_url, 'https://vpn.example.test');
  assert.strictEqual(form.value.future_option.preserved, true);
  assert.strictEqual(JSON.stringify(original), before, 'editing mutated the original prop');
  const fresh = Object.assign(config(), { client_id: 'fresh-group' });
  component.watch.value.handler.call(form, fresh);
  assert.strictEqual(form.draft.client_id, 'fresh-group');
  assert.strictEqual(form.subjectUsersText, JSON.stringify(fresh.subject_users, null, 2));
  assert.deepStrictEqual(Object.keys(form.errors), []);

  const posts = [];
  const snapshot = {
    id: 7, name: 'existing-group', bandwidth: 0,
    auth: { type: 'oidc', oidc: Object.assign(config(), { public_url: 'https://vpn.example.test' }) },
    auth_revision: 'revision-1', sso_secret_set: true,
  };
  const axios = {
    get: async () => ({ data: { code: 0, data: JSON.parse(JSON.stringify(snapshot)) } }),
    post: async (url, body, options) => {
      posts.push({ url, body: JSON.parse(JSON.stringify(body)), options });
      return { data: { code: 0, msg: 'saved' } };
    },
  };
  const groupComponent = readComponent(path.join(__dirname, '../pages/group/List.vue'),
    { axios, draggable: {}, SSOConfigForm: {} });
  const group = instantiate(groupComponent);
  const messages = [];
  group.$message = { error: message => messages.push(message), success() {} };
  group.$refs = {
    ruleForm: { clearValidate() {}, validate(callback) { callback(true); } },
    ssoConfigForm: { validate: async () => true },
  };
  group.getData = () => {};
  group.user_edit_dialog = false;

  await group.handleEdit({ id: 7 });
  assert.strictEqual(group.ssoSecretSet, true);
  assert.strictEqual(group.ruleForm.auth_revision, 'revision-1');
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.at(-1).body.sso_secret_action, 'preserve');
  assert.strictEqual(posts.at(-1).body.auth_revision, 'revision-1');
  assert.strictEqual(posts.at(-1).options.headers['Content-Type'], 'application/json');

  await group.handleEdit({ id: 7 });
  group.currentSSOConfig.client_secret = 'new-test-only-secret';
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.at(-1).body.sso_secret_action, 'replace');

  await group.handleEdit({ id: 7 });
  group.clearSSOSecret = true;
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.at(-1).body.sso_secret_action, 'clear');

  await group.handleEdit({ id: 7 });
  group.currentSSOConfig.issuer = 'https://other-idp.example.test';
  assert.strictEqual(group.ssoSecretSet, false);
  const previousPosts = posts.length;
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.length, previousPosts, 'changed provider silently reused the old secret');
  assert.ok(messages.at(-1).includes('身份平台'));
  assert.strictEqual(group.groupSaving, false);
  group.clearSSOSecret = true;
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.at(-1).body.sso_secret_action, 'clear');

  await group.handleEdit({ id: 7 });
  group.ruleForm.auth.type = 'local';
  await group.submitForm('ruleForm');
  assert.strictEqual(posts.at(-1).body.auth.type, 'local');
  assert.strictEqual(posts.at(-1).body.auth_revision, 'revision-1');

  await group.handleEdit({ id: 7 });
  group.ruleForm.stale_property = 'must disappear';
  await group.handleEdit('');
  assert.strictEqual(group.ruleForm.id, 0);
  assert.strictEqual(group.ruleForm.auth_revision, '');
  assert.strictEqual(group.ruleForm.stale_property, undefined);
  assert.strictEqual(group.savedSSOSecretSet, false);
  assert.strictEqual(group.clearSSOSecret, false);
  assert.strictEqual(group.ruleForm.auth.oidc.issuer, '');

  let resolveOldLoad;
  axios.get = () => new Promise(resolve => { resolveOldLoad = resolve; });
  const oldLoad = group.handleEdit({ id: 7 });
  await Promise.resolve();
  await group.handleEdit('');
  resolveOldLoad({ data: { code: 0, data: snapshot } });
  await oldLoad;
  assert.strictEqual(group.ruleForm.id, 0, 'late edit response overwrote a new-group form');
  assert.strictEqual(group.ruleForm.auth_revision, '');
  console.log('PASS: SSO component drafts/dirty events, normalized v-model, secret actions, revision preservation, and fresh group editing');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
