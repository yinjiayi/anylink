<template>
  <div class="sso-page">
    <div class="page-heading">
      <h1>OAuth2 / OIDC</h1>
      <p>配置 AnyConnect 网页单点登录。每个用户组可以使用独立的身份提供方和用户映射。</p>
    </div>

    <el-card shadow="never" class="group-card" v-loading="groupsLoading">
      <div class="group-picker">
        <label for="sso-group">配置用户组</label>
        <el-select id="sso-group" :value="groupId" filterable placeholder="请选择用户组"
          :disabled="loading || saving || !groups.length" @change="selectGroup">
          <el-option v-for="group in groups" :key="group.id" :label="group.name" :value="group.id" />
        </el-select>
        <el-tag v-if="loaded" :type="isSavedSSO ? 'success' : 'info'" size="small">
          当前认证：{{ authLabel(savedType) }}
        </el-tag>
        <el-tag v-if="dirty" type="warning" size="small">未保存</el-tag>
        <router-link to="/admin/group/list">管理用户组</router-link>
      </div>
      <el-alert v-if="groupsError" :title="groupsError" type="error" :closable="false" show-icon />
      <div v-else-if="!groupsLoading && !groups.length" class="empty-state">
        暂无用户组，请先在“用户组列表”中创建用户组，再配置 SSO。
      </div>
      <el-button v-if="groupsError" size="small" @click="loadGroups">重新加载用户组</el-button>
    </el-card>

    <div v-loading="loading" class="config-area">
      <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" show-icon />
      <el-button v-if="loadError" size="small" @click="loadGroup(groupId)">重试</el-button>
      <div v-if="loaded" class="config-grid">
        <el-card shadow="never" class="provider-card">
          <div slot="header" class="card-heading">
            <span>身份提供方</span>
            <span class="group-name">{{ groupName }}</span>
          </div>
          <el-alert v-if="groupStatus !== 1" title="此用户组已停用，保存配置后仍需在用户组列表启用才能登录。"
            type="warning" :closable="false" show-icon class="notice" />
          <el-alert v-if="!isSavedSSO" :title="'保存后，此用户组将从' + authLabel(savedType) + '认证切换为网页 SSO。'"
            type="info" :closable="false" show-icon class="notice" />
          <fieldset :disabled="saving" class="config-fields">
            <div class="protocol-picker">
              <span>认证协议</span>
              <el-radio-group :value="providerType" @input="changeType">
                <el-radio-button label="oidc">OIDC（推荐）</el-radio-button>
                <el-radio-button label="oauth2">OAuth2</el-radio-button>
              </el-radio-group>
            </div>
            <SSOConfigForm :key="groupId + ':' + providerType + ':' + formRevision" ref="configForm"
              v-model="config" :type="providerType" :secret-set="secretSet" @dirty="dirty = true" />
            <div v-if="savedSecretSet" class="secret-control">
              <p v-if="!secretSet" class="secret-hint">身份平台或 Client ID 已变更，请填写新密钥，或明确选择不使用密钥。</p>
              <el-checkbox v-model="clearSecret" :disabled="!!config.client_secret" @change="dirty = true">
                {{ secretSet ? '清除已保存的 Client Secret（仅用于公开客户端）' : '新的身份平台使用公开客户端（不使用 Client Secret）' }}
              </el-checkbox>
            </div>
          </fieldset>
          <div class="save-bar">
            <el-button type="primary" :loading="saving" @click="save">保存配置</el-button>
            <el-button :disabled="saving" @click="reload">重新加载</el-button>
            <span>保存后对新的登录请求生效</span>
          </div>
        </el-card>

        <aside class="setup-guide">
          <el-card shadow="never">
            <div slot="header">接入步骤</div>
            <ol>
              <li>在身份平台创建应用，启用授权码流程与 PKCE S256。</li>
              <li>填写 VPN 外部地址，将表单生成的回调地址登记到身份平台。</li>
              <li>填写应用信息，将身份平台的稳定身份映射到已有 AnyLink 用户。</li>
              <li>保存后，在 AnyConnect 选择此用户组，验证网页登录和 VPN 连接。</li>
            </ol>
            <p>映射用户必须已启用、未过期，并属于当前用户组。空映射将拒绝所有 SSO 登录。</p>
            <router-link to="/admin/user/list">查看 AnyLink 用户</router-link>
          </el-card>
          <p class="help-note">需要改回密码认证时，请到“用户组列表 → 编辑 → 认证方式”中修改。</p>
        </aside>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import SSOConfigForm from '@/components/SSOConfigForm';
import { ssoDefaults } from '@/utils/ssoConfig';

export default {
  name: 'SSOSettings',
  components: { SSOConfigForm },
  data() {
    return {
      groups: [], groupsLoading: false, groupsError: '',
      groupId: null, groupName: '', groupStatus: 1,
      loading: false, loaded: false, loadError: '', saving: false,
      providerType: 'oidc', savedType: 'local', revision: '',
      savedConfig: {}, savedSecretSet: false, clearSecret: false,
      drafts: { oidc: ssoDefaults('oidc'), oauth2: ssoDefaults('oauth2') },
      dirty: false, formRevision: 0,
    };
  },
  computed: {
    config: {
      get() { return this.drafts[this.providerType]; },
      set(value) { this.$set(this.drafts, this.providerType, value); },
    },
    isSavedSSO() { return ['oidc', 'oauth2'].includes(this.savedType); },
    secretSet() {
      if (!this.savedSecretSet || this.providerType !== this.savedType) return false;
      const fields = this.providerType === 'oidc'
        ? ['issuer', 'client_id'] : ['authorization_url', 'token_url', 'userinfo_url', 'client_id'];
      return fields.every(field => (this.config[field] || '') === (this.savedConfig[field] || ''));
    },
  },
  created() {
    this.$emit('update:route_path', this.$route.path);
    this.$emit('update:route_name', ['基础信息', 'OAuth2 / OIDC']);
    this.loadGroups();
  },
  mounted() { window.addEventListener('beforeunload', this.beforeUnload); },
  beforeDestroy() { window.removeEventListener('beforeunload', this.beforeUnload); },
  beforeRouteLeave(to, from, next) {
    if (this.saving) { next(false); return; }
    this.canDiscard().then(allowed => next(allowed));
  },
  methods: {
    authLabel(type) {
      return { local: '本地密码', radius: 'RADIUS', ldap: 'LDAP', wxwork: '企业微信',
        oidc: 'OIDC', oauth2: 'OAuth2' }[type] || type;
    },
    beforeUnload(event) {
      if (this.dirty || this.saving) { event.preventDefault(); event.returnValue = ''; }
    },
    async canDiscard() {
      if (!this.dirty) return true;
      try {
        await this.$confirm('当前配置尚未保存，是否放弃修改？', '未保存的配置', {
          confirmButtonText: '放弃修改', cancelButtonText: '继续编辑', type: 'warning',
        });
        return true;
      } catch (_) { return false; }
    },
    async loadGroups() {
      this.groupsLoading = true;
      this.groupsError = '';
      try {
        const { data } = await axios.get('/group/names_ids');
        if (data.code !== 0) throw new Error(data.msg);
        this.groups = data.data.datas || [];
        if (this.groups.length) {
          const requested = Number(this.$route.query.group);
          const initial = this.groups.find(group => group.id === requested) || this.groups[0];
          await this.loadGroup(initial.id);
        }
      } catch (error) {
        this.groupsError = error.message || '加载用户组失败，请重试。';
      } finally { this.groupsLoading = false; }
    },
    async selectGroup(id) {
      if (id === this.groupId || !await this.canDiscard()) return;
      await this.loadGroup(id);
    },
    async loadGroup(id) {
      this.groupId = id;
      this.loading = true;
      this.loaded = false;
      this.loadError = '';
      try {
        const { data } = await axios.get('/group/sso', { params: { id } });
        if (data.code !== 0) throw new Error(data.msg);
        this.applySnapshot(data.data);
      } catch (error) {
        this.loadError = error.message || '加载认证配置失败，请重试。';
      } finally { this.loading = false; }
    },
    applySnapshot(data) {
      this.groupName = data.name;
      this.groupStatus = data.status;
      this.savedType = data.auth_type || 'local';
      this.providerType = this.isSavedSSO ? this.savedType : 'oidc';
      this.revision = data.revision;
      this.savedConfig = JSON.parse(JSON.stringify(data.config || {}));
      this.savedSecretSet = !!data.secret_set;
      this.drafts = { oidc: ssoDefaults('oidc'), oauth2: ssoDefaults('oauth2') };
      if (this.isSavedSSO) this.$set(this.drafts, this.providerType,
        Object.assign(ssoDefaults(this.providerType), data.config, { client_secret: '' }));
      this.clearSecret = false;
      this.dirty = false;
      this.formRevision++;
      this.loaded = true;
    },
    changeType(type) {
      this.providerType = type;
      this.clearSecret = false;
      this.dirty = true;
    },
    async reload() {
      if (await this.canDiscard()) await this.loadGroup(this.groupId);
    },
    async save() {
      if (this.saving || !this.loaded || !await this.$refs.configForm.validate()) return;
      if (this.saving) return;
      if (this.savedSecretSet && !this.secretSet && !this.config.client_secret && !this.clearSecret) {
        this.$message.error('身份平台或 Client ID 已变更，请填写新密钥，或选择公开客户端。');
        return;
      }
      this.saving = true;
      try {
        const secretAction = this.config.client_secret ? 'replace' : this.clearSecret ? 'clear' : 'preserve';
        const { data } = await axios.post('/group/sso/set', {
          id: this.groupId, config: Object.assign({}, this.config, { type: this.providerType }),
          revision: this.revision, secret_action: secretAction,
        }, { headers: { 'Content-Type': 'application/json' } });
        if (data.code !== 0) {
          const messages = {
            sso_config_conflict: '认证配置已被其他页面修改，请重新加载后再保存。',
            sso_provider_changed_secret_action_required: '身份平台已变更，请填写新密钥，或选择公开客户端。',
            sso_group_not_found: '此用户组已删除，请重新加载用户组列表。',
            sso_secret_required: '请输入新的 Client Secret。',
            sso_database_error: '配置存储失败，请稍后重试。',
          };
          throw new Error(messages[data.msg] || data.msg);
        }
        this.applySnapshot(data.data);
        this.$message.success('OAuth2 / OIDC 配置已保存');
      } catch (error) {
        this.$message.error(error.message || '保存失败，请重试。');
      } finally { this.saving = false; }
    },
  },
};
</script>

<style scoped>
.sso-page { max-width: 1180px; margin: 0 auto; color: #303133; }
.page-heading { margin-bottom: 22px; }
h1 { margin: 0 0 10px; font-size: 24px; font-weight: 600; }
.page-heading p, .help-note { color: #606266; line-height: 1.7; margin: 0; font-size: 14px; }
.group-card { margin-bottom: 20px; }
.group-picker { display: flex; align-items: center; flex-wrap: wrap; gap: 14px; }
.group-picker label { font-size: 14px; font-weight: 500; }
.group-picker .el-select { width: 250px; }
.group-picker a { margin-left: auto; }
a { color: #409eff; text-decoration: none; font-size: 14px; }
.empty-state { padding-top: 18px; color: #909399; font-size: 14px; }
.config-area { min-height: 80px; }
.config-grid { display: grid; grid-template-columns: minmax(0, 1fr) 250px; gap: 20px; align-items: start; }
.card-heading { display: flex; gap: 12px; justify-content: space-between; font-weight: 500; }
.group-name { color: #909399; font-size: 13px; overflow-wrap: anywhere; }
.notice { margin-bottom: 20px; }
.config-fields { padding: 0; margin: 0; border: 0; min-width: 0; }
.protocol-picker { display: flex; align-items: center; flex-wrap: wrap; gap: 18px; margin-bottom: 24px; font-size: 14px; }
.secret-control { margin: 0 0 20px; }
.secret-hint { font-size: 13px; color: #e6a23c; line-height: 1.6; }
.config-fields:disabled { pointer-events: none; opacity: 0.7; }
.secret-control >>> .el-checkbox__label { white-space: normal; line-height: 1.6; vertical-align: middle; }
.save-bar { border-top: 1px solid #ebeef5; padding-top: 20px; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.save-bar .el-button + .el-button { margin-left: 0; }
.save-bar span { font-size: 12px; color: #909399; }
.setup-guide { font-size: 13px; color: #606266; line-height: 1.8; }
.setup-guide ol { padding-left: 20px; margin: 0; }
.setup-guide li { margin-bottom: 16px; }
.setup-guide p { margin: 16px 0; }
.setup-guide .help-note { font-size: 12px; }
@media (max-width: 1150px) { .config-grid { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 600px) { .group-picker .el-select { width: 100%; } .group-picker a { margin-left: 0; } }
</style>
