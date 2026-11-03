<template>
  <div class="sso-config-form">
    <el-alert v-if="errors.type" :title="errors.type" type="error" :closable="false"></el-alert>
    <sso-field label="VPN外部地址" :target="fieldId('public_url')" :error="errors.public_url">
      <el-input :id="fieldId('public_url')" :value="draft.public_url" @input="updateField('public_url', $event)"
        placeholder="https://vpn.example.com"></el-input>
      <p class="sso-hint">填写客户端访问的 HTTPS 地址，可包含端口，不含路径。</p>
      <p class="sso-hint">身份提供方的回调地址：<span class="sso-callback">{{ callbackURL }}</span></p>
    </sso-field>
    <sso-field v-if="type === 'oidc'" label="Issuer" :target="fieldId('issuer')" :error="errors.issuer">
      <el-input :id="fieldId('issuer')" :value="draft.issuer" @input="updateField('issuer', $event)"
        placeholder="https://login.example.com/realms/company"></el-input>
      <p class="sso-hint">必须与身份提供方公布的 issuer 完全一致，服务端自动发现授权和令牌端点。</p>
    </sso-field>
    <template v-if="type === 'oauth2'">
      <sso-field label="授权端点" :target="fieldId('authorization_url')" :error="errors.authorization_url">
        <el-input :id="fieldId('authorization_url')" :value="draft.authorization_url"
          @input="updateField('authorization_url', $event)"
          placeholder="https://login.example.com/oauth/authorize"></el-input>
      </sso-field>
      <sso-field label="令牌端点" :target="fieldId('token_url')" :error="errors.token_url">
        <el-input :id="fieldId('token_url')" :value="draft.token_url" @input="updateField('token_url', $event)"
          placeholder="https://login.example.com/oauth/token"></el-input>
      </sso-field>
      <sso-field label="用户信息端点" :target="fieldId('userinfo_url')" :error="errors.userinfo_url">
        <el-input :id="fieldId('userinfo_url')" :value="draft.userinfo_url" @input="updateField('userinfo_url', $event)"
          placeholder="https://login.example.com/api/user"></el-input>
      </sso-field>
      <sso-field label="身份字段" :target="fieldId('subject_claim')" :error="errors.subject_claim">
        <el-input :id="fieldId('subject_claim')" :value="draft.subject_claim" @input="updateField('subject_claim', $event)"
          placeholder="id"></el-input>
        <p class="sso-hint">用户信息 JSON 顶层的不可变唯一字段，例如 id。不要使用可修改的显示名或邮箱。</p>
      </sso-field>
    </template>
    <sso-field label="Client ID" :target="fieldId('client_id')" :error="errors.client_id">
      <el-input :id="fieldId('client_id')" :value="draft.client_id" @input="updateField('client_id', $event)"
        autocomplete="off"></el-input>
    </sso-field>
    <sso-field label="Client Secret" :target="fieldId('client_secret')" :error="errors.client_secret">
      <el-input :id="fieldId('client_secret')" type="password" :value="draft.client_secret"
        @input="updateField('client_secret', $event)" :placeholder="secretPlaceholder"
        autocomplete="new-password" show-password></el-input>
      <p v-if="secretSet" class="sso-hint">已保存密钥不会回显；留空保留原密钥，填写新值将替换。</p>
      <p v-else class="sso-hint">按身份提供方的客户端类型填写；仅允许公开客户端在提供方支持 PKCE 时留空。</p>
    </sso-field>
    <sso-field label="Scopes" :target="fieldId('scopes')" :error="errors.scopes">
      <el-input :id="fieldId('scopes')" :value="scopesText" @input="updateScopes"
        placeholder="多个 scope 用空格分隔"></el-input>
      <p class="sso-hint">OIDC 必须包含 openid。仅申请登录所需权限。</p>
    </sso-field>
    <sso-field label="浏览器模式" :target="fieldId('browser_mode')" :error="errors.browser_mode">
      <el-radio-group :id="fieldId('browser_mode')" :value="draft.browser_mode"
        @input="updateField('browser_mode', $event)" aria-label="浏览器模式">
        <el-radio label="auto">自动协商</el-radio>
        <el-radio label="internal">内置浏览器</el-radio>
        <el-radio label="external">系统浏览器</el-radio>
      </el-radio-group>
      <p class="sso-hint">自动模式按客户端声明的 SSO 能力选择。系统浏览器要求兼容客户端和本地回调组件，需在实际终端验收。</p>
    </sso-field>
    <sso-field label="用户身份映射" :target="fieldId('subject_users')" :error="errors.subject_users">
      <el-input :id="fieldId('subject_users')" type="textarea" :rows="5" :value="subjectUsersText"
        @input="updateSubjectUsers" placeholder='{"身份提供方的稳定subject": "AnyLink用户名"}'></el-input>
      <p class="sso-hint">JSON 对象：OIDC 的 sub（或 OAuth2 身份字段值）映射到已有 AnyLink 用户名。用户须启用且属于此组；未映射用户不能登录，不会自动创建账号。</p>
    </sso-field>
    <div class="sso-policy-note">
      <el-alert title="请在身份提供方启用所需 MFA 策略。此组的 SSO 流程不追加 AnyLink 本地 TOTP 验证。"
        type="info" :closable="false" show-icon></el-alert>
    </div>
  </div>
</template>

<script>
import { cloneSSOConfig, normalizeSSOConfig, parseSubjectUsers } from '@/utils/ssoConfig';

// This field intentionally does not inject/register with Element UI's elForm.
// Both a standalone page and an existing group el-form can own this component.
const SSOField = {
  props: {
    label: { type: String, required: true },
    target: { type: String, required: true },
    error: { type: String, default: '' },
  },
  render(h) {
    return h('div', { class: ['sso-field', { 'is-error': !!this.error }] }, [
      h('label', { class: 'sso-field-label', attrs: { for: this.target } }, this.label),
      h('div', { class: 'sso-field-content' }, [
        this.$slots.default,
        this.error ? h('div', { class: 'sso-field-error', attrs: { role: 'alert' } }, this.error) : null,
      ]),
    ]);
  },
};

export default {
  name: 'SSOConfigForm',
  components: { 'sso-field': SSOField },
  props: {
    type: { type: String, required: true, validator: value => ['oidc', 'oauth2'].includes(value) },
    value: { type: Object, default: () => ({}) },
    secretSet: { type: Boolean, default: false },
  },
  data() {
    return {
      draft: cloneSSOConfig(this.type, this.value),
      scopesText: '',
      subjectUsersText: '{}',
      errors: {},
      lastEmitted: '',
    };
  },
  computed: {
    callbackURL() {
      const origin = typeof this.draft.public_url === 'string'
        ? this.draft.public_url.trim().replace(/\/$/, '') : '';
      return origin ? origin + '/+CSCOE+/sso/callback' : '填写 VPN 外部地址后显示';
    },
    secretPlaceholder() {
      return this.secretSet ? '留空保留已保存密钥' : '';
    },
  },
  watch: {
    value: {
      deep: true,
      handler(value) {
        // A v-model echo must not remove trailing spaces or invalid JSON that
        // the user is still editing.
        if (JSON.stringify(value) !== this.lastEmitted) this.loadValue(value);
      },
    },
    type() {
      this.loadValue(this.value);
    },
  },
  created() {
    this.loadValue(this.value);
  },
  methods: {
    fieldId(field) {
      return 'sso-' + this._uid + '-' + field;
    },
    loadValue(value) {
      this.draft = cloneSSOConfig(this.type, value);
      if (!this.draft.browser_mode) this.draft.browser_mode = 'auto';
      this.scopesText = Array.isArray(this.draft.scopes) ? this.draft.scopes.join(' ') : '';
      this.subjectUsersText = JSON.stringify(this.draft.subject_users || {}, null, 2);
      this.errors = {};
      this.lastEmitted = '';
    },
    emitConfig() {
      const value = cloneSSOConfig(this.type, this.draft);
      this.lastEmitted = JSON.stringify(value);
      this.$emit('input', value);
    },
    edited(field) {
      this.$delete(this.errors, field);
      this.$emit('dirty');
    },
    updateField(field, value) {
      this.$set(this.draft, field, value);
      this.edited(field);
      this.emitConfig();
    },
    updateScopes(value) {
      this.scopesText = value;
      this.draft.scopes = Array.from(new Set(value.trim().split(/\s+/).filter(Boolean)));
      this.edited('scopes');
      this.emitConfig();
    },
    updateSubjectUsers(value) {
      this.subjectUsersText = value;
      this.edited('subject_users');
      try {
        this.draft.subject_users = parseSubjectUsers(value);
        this.emitConfig();
      } catch (error) {
        // Keep the incomplete text locally. validate() blocks saving it, and
        // dirty is emitted even when there is no typed value to send upstream.
      }
    },
    async validate() {
      const result = normalizeSSOConfig(this.type, this.draft, this.scopesText, this.subjectUsersText);
      this.errors = result.errors;
      if (Object.keys(result.errors).length > 0) {
        await this.$nextTick();
        const field = this.$el.querySelector('.is-error input, .is-error textarea');
        if (field) field.focus();
        return false;
      }
      this.draft = result.config;
      this.emitConfig();
      return true;
    },
  },
};
</script>

<style scoped>
.sso-config-form {
  width: 100%;
}
.sso-config-form ::v-deep .sso-field {
  display: grid;
  grid-template-columns: 100px minmax(0, 1fr);
  margin-bottom: 22px;
}
.sso-config-form ::v-deep .sso-field-label {
  color: #606266;
  font-size: 14px;
  line-height: 40px;
  padding-right: 12px;
  text-align: right;
}
.sso-config-form ::v-deep .sso-field-content {
  min-width: 0;
  line-height: 40px;
}
.sso-config-form ::v-deep .sso-field-error {
  color: #f56c6c;
  font-size: 12px;
  line-height: 1.5;
  padding-top: 4px;
}
.sso-config-form ::v-deep .is-error input,
.sso-config-form ::v-deep .is-error textarea {
  border-color: #f56c6c;
}
.sso-hint {
  color: #909399;
  font-size: 12px;
  line-height: 1.6;
  margin: 4px 0 0;
  overflow-wrap: anywhere;
}
.sso-callback {
  user-select: all;
}
.sso-policy-note {
  margin: 0 0 22px 100px;
}
</style>
