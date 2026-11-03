<template>
  <div>
    <el-card>
      <el-form :inline="true">
        <el-form-item>
          <el-button size="small" type="primary" icon="el-icon-plus" @click="handleEdit('')">添加
          </el-button>
        </el-form-item>
      </el-form>

      <el-table ref="multipleTable" :data="tableData" border>

        <el-table-column sortable="true" prop="id" label="ID" width="60">
        </el-table-column>

        <el-table-column prop="name" label="组名">
        </el-table-column>

        <el-table-column prop="note" label="备注">
        </el-table-column>

        <el-table-column prop="allow_lan" label="本地网络">
          <template slot-scope="scope">
            <el-switch v-model="scope.row.allow_lan" disabled>
            </el-switch>
          </template>
        </el-table-column>

        <el-table-column prop="bandwidth" label="带宽限制" width="90">
          <template slot-scope="scope">
            <el-row v-if="scope.row.bandwidth > 0">{{ convertBandwidth(scope.row.bandwidth, 'BYTE', 'Mbps') }} Mbps
            </el-row>
            <el-row v-else>不限</el-row>
          </template>
        </el-table-column>

        <el-table-column prop="client_dns" label="客户端DNS" width="160">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.client_dns" :key="inx">{{ item.val }}</el-row>
          </template>
        </el-table-column>

        <el-table-column prop="route_include" label="路由包含" width="180">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.route_include.slice(0, readMinRows)" :key="inx">{{
              item.val
              }}
            </el-row>
            <div v-if="scope.row.route_include.length > readMinRows">
              <div v-if="readMore[`ri_${scope.row.id}`]">
                <el-row v-for="(item, inx) in scope.row.route_include.slice(readMinRows)" :key="inx">{{
                  item.val
                  }}
                </el-row>
              </div>
              <el-button size="mini" type="text" @click="toggleMore(`ri_${scope.row.id}`)">
                {{ readMore[`ri_${scope.row.id}`] ? "▲ 收起" : "▼ 更多" }}
              </el-button>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="route_exclude" label="路由排除" width="180">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.route_exclude.slice(0, readMinRows)" :key="inx">{{
              item.val
              }}
            </el-row>
            <div v-if="scope.row.route_exclude.length > readMinRows">
              <div v-if="readMore[`re_${scope.row.id}`]">
                <el-row v-for="(item, inx) in scope.row.route_exclude.slice(readMinRows)" :key="inx">{{
                  item.val
                  }}
                </el-row>
              </div>
              <el-button size="mini" type="text" @click="toggleMore(`re_${scope.row.id}`)">
                {{ readMore[`re_${scope.row.id}`] ? "▲ 收起" : "▼ 更多" }}
              </el-button>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="link_acl" label="权限控制" min-width="180">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.link_acl.slice(0, readMinRows)" :key="inx">
              {{ item.action }} => {{ item.val }} : {{ item.port }}
            </el-row>
            <div v-if="scope.row.link_acl.length > readMinRows">
              <div v-if="readMore[`la_${scope.row.id}`]">
                <el-row v-for="(item, inx) in scope.row.link_acl.slice(readMinRows)" :key="inx">
                  {{ item.action }} => {{ item.val }} : {{ item.port }}
                </el-row>
              </div>
              <el-button size="mini" type="text" @click="toggleMore(`la_${scope.row.id}`)">
                {{ readMore[`la_${scope.row.id}`] ? "▲ 收起" : "▼ 更多" }}
              </el-button>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="status" label="状态" width="70">
          <template slot-scope="scope">
            <el-tag v-if="scope.row.status === 1" type="success">可用</el-tag>
            <el-tag v-else type="danger">停用</el-tag>
          </template>

        </el-table-column>

        <el-table-column prop="updated_at" label="更新时间" :formatter="tableDateFormat">
        </el-table-column>

        <el-table-column label="操作" width="150">
          <template slot-scope="scope">
            <el-button size="mini" type="primary" @click="handleEdit(scope.row)">编辑
            </el-button>

            <el-popconfirm style="margin-left: 10px" @confirm="handleDel(scope.row)" title="确定要删除用户组吗？">
              <el-button slot="reference" size="mini" type="danger">删除
              </el-button>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>

      <div class="sh-20"></div>

      <el-pagination background layout="prev, pager, next" :pager-count="11" @current-change="pageChange"
        :current-page="page" :total="count">
      </el-pagination>

    </el-card>

    <!--新增、修改弹出框-->
    <el-dialog :close-on-click-modal="false" title="用户组" :visible.sync="user_edit_dialog" width="850px"
      :show-close="!groupSaving" :close-on-press-escape="!groupSaving" @close='closeDialog' center>

      <el-form :model="ruleForm" :rules="rules" ref="ruleForm" label-width="100px" class="ruleForm"
        :disabled="editLoading || groupSaving" v-loading="editLoading">
        <el-tabs v-model="activeTab" :before-leave="beforeTabLeave">
          <el-tab-pane label="通用" name="general">
            <el-form-item label="用户组ID" prop="id">
              <el-input v-model="ruleForm.id" disabled></el-input>
            </el-form-item>

            <el-form-item label="组名" prop="name">
              <el-input v-model="ruleForm.name" :disabled="ruleForm.id > 0"></el-input>
            </el-form-item>

            <el-form-item label="备注" prop="note">
              <el-input v-model="ruleForm.note"></el-input>
            </el-form-item>

            <el-form-item label="带宽限制" prop="bandwidth_format" style="width:260px;">
              <el-input v-model="ruleForm.bandwidth_format"
                oninput="value= value.match(/\d+(\.\d{0,2})?/) ? value.match(/\d+(\.\d{0,2})?/)[0] : ''">
                <template slot="append">Mbps</template>
              </el-input>
            </el-form-item>
            <el-form-item label="排除本地网络" prop="allow_lan">
              <!--  active-text="开启后 用户本地所在网段将不通过anylink加密传输" -->
              <el-switch v-model="ruleForm.allow_lan"></el-switch>
              <div class="msg-info">
                注：本地网络 指的是：
                运行 anyconnect 客户端的PC 所在的的网络，即本地路由网段。
                开启后，PC本地路由网段的数据就不会走隧道链路转发数据了。
                同时 anyconnect 客户端需要勾选本地网络(Allow Local Lan)的开关，功能才能生效。
              </div>
            </el-form-item>

            <el-form-item label="客户端DNS" prop="client_dns">
              <el-row class="msg-info">
                <el-col :span="20">输入IP格式如: 192.168.0.10</el-col>
                <el-col :span="4">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.client_dns)"></el-button>
                </el-col>
              </el-row>
              <el-row v-for="(item, index) in ruleForm.client_dns" :key="index" style="margin-bottom: 5px" :gutter="10">
                <el-col :span="10">
                  <el-input v-model="item.val"></el-input>
                </el-col>
                <el-col :span="12">
                  <el-input v-model="item.note" placeholder="备注"></el-input>
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="danger" icon="el-icon-minus" circle
                    @click.prevent="removeDomain(ruleForm.client_dns, index)"></el-button>
                </el-col>
              </el-row>
            </el-form-item>

            <el-form-item label="内网域名" prop="split_dns">
              <el-row class="msg-info">
                <el-col :span="20">(分割DNS)一般留空。如果输入域名，只有配置的域名(包含子域名)走配置的dns</el-col>
                <el-col :span="4">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.split_dns)"></el-button>
                </el-col>
              </el-row>
              <el-row v-for="(item, index) in ruleForm.split_dns" :key="index" style="margin-bottom: 5px" :gutter="10">
                <el-col :span="10">
                  <el-input v-model="item.val"></el-input>
                </el-col>
                <el-col :span="12">
                  <el-input v-model="item.note" placeholder="备注"></el-input>
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="danger" icon="el-icon-minus" circle
                    @click.prevent="removeDomain(ruleForm.split_dns, index)"></el-button>
                </el-col>
              </el-row>
            </el-form-item>

            <el-form-item label="状态" prop="status">
              <el-radio-group v-model="ruleForm.status">
                <el-radio :label="1" border>启用</el-radio>
                <el-radio :label="0" border>停用</el-radio>
              </el-radio-group>
            </el-form-item>
          </el-tab-pane>

          <el-tab-pane label="认证方式" name="authtype">
            <el-form-item label="认证" prop="authtype">
              <el-radio-group v-model="ruleForm.auth.type" @change="authTypeChange">
                <el-radio label="local" border>本地</el-radio>
                <el-radio label="radius" border>Radius</el-radio>
                <el-radio label="ldap" border>LDAP</el-radio>
                <el-radio label="wxwork" border>企业微信</el-radio>
                <el-radio label="oidc" border>OIDC</el-radio>
                <el-radio label="oauth2" border>OAuth2</el-radio>
              </el-radio-group>
            </el-form-item>
            <SSOConfigForm v-if="user_edit_dialog && isSSOAuth" ref="ssoConfigForm"
              :key="ruleForm.id + ':' + ruleForm.auth.type" :type="ruleForm.auth.type"
              v-model="ruleForm.auth[ruleForm.auth.type]" :secret-set="ssoSecretSet"></SSOConfigForm>
            <el-form-item v-if="isSSOAuth && savedSSOSecretSet" label="密钥操作">
              <div v-if="!ssoSecretSet" class="msg-info">身份平台或 Client ID 已变更，请填写新密钥，或明确选择不使用密钥。</div>
              <el-checkbox v-model="clearSSOSecret" :disabled="!!currentSSOConfig.client_secret">
                {{ ssoSecretSet ? '清除已保存的 Client Secret（仅用于公开客户端）' : '新的身份平台使用公开客户端（不使用 Client Secret）' }}
              </el-checkbox>
            </el-form-item>
            <template v-if="ruleForm.auth.type == 'radius'">
              <el-form-item label="服务器地址" prop="auth.radius.addr"
                :rules="this.ruleForm.auth.type == 'radius' ? this.rules['auth.radius.addr'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.radius.addr" placeholder="例如 ip:1812"></el-input>
              </el-form-item>
              <el-form-item label="密钥" prop="auth.radius.secret"
                :rules="this.ruleForm.auth.type == 'radius' ? this.rules['auth.radius.secret'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.radius.secret" placeholder=""></el-input>
              </el-form-item>
              <el-form-item label="Nasip" prop="auth.radius.nasip">
                <el-input v-model="ruleForm.auth.radius.nasip" placeholder=""></el-input>
              </el-form-item>
            </template>

            <template v-if="ruleForm.auth.type == 'ldap'">
              <el-form-item label="服务器地址" prop="auth.ldap.addr"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.addr'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.ldap.addr" placeholder="例如 ip:389 / 域名:389"></el-input>
              </el-form-item>
              <el-form :inline="true" label-width="100px" class="ruleForm">
                <el-form-item label="开启TLS" prop="auth.ldap.tls">
                  <el-switch v-model="ruleForm.auth.ldap.tls"></el-switch>
                </el-form-item>
                <el-form-item label="开启OTP" prop="auth.ldap.enable_otp">
                  <el-switch v-model="ruleForm.auth.ldap.enable_otp" @change="handleOtpChange">
                  </el-switch>
                  <el-tooltip content="全局关闭\启用ldap用户otp验证,开启后会自动同步用户到本地,用户界面可手动管理OTP秘钥." placement="top">
                    <i class="el-icon-info" style="margin-left: 10px; cursor: pointer; color: #888;"></i>
                  </el-tooltip>
                </el-form-item>
                <el-form-item label="用户状态过滤" prop="auth.ldap.sync_user_status">
                  <el-switch v-model="ruleForm.auth.ldap.sync_user_status"></el-switch>
                  <el-tooltip content="开启后，在同步LDAP用户时只会同步状态正常的用户（未禁用、未锁定、未过期）" placement="top">
                    <i class="el-icon-info" style="margin-left: 10px; cursor: pointer; color: #888;"></i>
                  </el-tooltip>
                </el-form-item>
              </el-form>
              <el-form-item label="管理员 DN" prop="auth.ldap.bind_name"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.bind_name'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.ldap.bind_name" placeholder="例如 CN=bindadmin,DC=abc,DC=COM"></el-input>
              </el-form-item>
              <el-form-item label="管理员密码" prop="auth.ldap.bind_pwd"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.bind_pwd'] : [{ required: false }]">
                <el-input type="password" v-model="ruleForm.auth.ldap.bind_pwd" placeholder=""></el-input>
              </el-form-item>
              <el-form-item label="Base DN" prop="auth.ldap.base_dn"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.base_dn'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.ldap.base_dn" placeholder="例如 DC=abc,DC=com"></el-input>
              </el-form-item>
              <el-form-item label="用户对象类" prop="auth.ldap.object_class"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.object_class'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.ldap.object_class"
                  placeholder="例如 person / user / posixAccount"></el-input>
              </el-form-item>
              <el-form-item label="用户唯一ID" prop="auth.ldap.search_attr"
                :rules="this.ruleForm.auth.type == 'ldap' ? this.rules['auth.ldap.search_attr'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.ldap.search_attr"
                  placeholder="例如 sAMAccountName / uid / cn"></el-input>
              </el-form-item>
              <el-form-item label="受限用户组" prop="auth.ldap.member_of">
                <el-input v-model="ruleForm.auth.ldap.member_of"
                  placeholder="选填, 只允许指定组登入, 例如 CN=HomeWork,DC=abc,DC=com"></el-input>
              </el-form-item>
            </template>
            <template v-if="ruleForm.auth.type == 'wxwork'">
              <el-form-item label="企业ID" prop="auth.wxwork.corp_id"
                :rules="this.ruleForm.auth.type == 'wxwork' ? this.rules['auth.wxwork.corp_id'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.wxwork.corp_id" placeholder="例如 ww7164hdf7kc84073"></el-input>
              </el-form-item>
              <el-form-item label="应用ID" prop="auth.wxwork.agent_id"
                :rules="this.ruleForm.auth.type == 'wxwork' ? this.rules['auth.wxwork.agent_id'] : [{ required: false }]">
                <el-input v-model="ruleForm.auth.wxwork.agent_id" placeholder="例如 1000001"></el-input>
              </el-form-item>
              <el-form-item label="应用Secret" prop="auth.wxwork.secret"
                :rules="this.ruleForm.auth.type == 'wxwork' ? this.rules['auth.wxwork.secret'] : [{ required: false }]">
                <el-input type="password" v-model="ruleForm.auth.wxwork.secret" placeholder="应用的Secret密钥"></el-input>
              </el-form-item>
              <el-form-item label="允许的部门" prop="auth.wxwork.allowed_departments">
                <el-input v-model="ruleForm.auth.wxwork.allowed_departments" placeholder="请输入部门ID，多个用逗号分隔，留空表示不限制部门">
                </el-input>
                <div style="font-size: 12px; color: #909399; margin-top: 5px;">
                  提示：部门ID可在企业微信管理后台的"通讯录"中查看，多个部门ID用英文逗号分隔，留空表示允许所有企微用户登录。
                </div>
              </el-form-item>
              <el-form-item label="浏览器选择">
                <el-radio-group v-model="ruleForm.auth.wxwork.use_default_browser">
                  <el-radio :label="false">内置浏览器</el-radio>
                  <el-radio :label="true">默认浏览器</el-radio>
                </el-radio-group>
                <div style="font-size: 12px; color: #909399; line-height: 1.6; margin-top: 5px;">
                  提示：使用默认浏览器可避免兼容性问题，开启后扫码将跳转至系统浏览器。
                </div>
              </el-form-item>

              <el-form-item label="">
                <div
                  style="background-color: #FDF6EC; border: 1px solid #F5DAB1; color: #E6A23C; padding: 8px 16px; border-radius: 4px; font-size: 13px; line-height: 1.5;display: flex;align-items: center;">
                  <i class="el-icon-warning" style="margin-right: 8px; font-size: 16px;"></i>
                  <span>注：企微扫码登录暂时仅支持PC端Cisco Anyconnect客户端。</span>
                </div>
              </el-form-item>
            </template>
          </el-tab-pane>

          <el-tab-pane label="路由设置" name="route">
            <el-form-item label="包含路由" prop="route_include">
              <el-row class="msg-info">
                <el-col :span="18">输入CIDR格式如: 192.168.1.0/24</el-col>
                <el-col :span="2">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.route_include)"></el-button>
                </el-col>
                <el-col :span="4">
                  <el-button size="mini" type="info" icon="el-icon-edit" circle
                    @click.prevent="openIpListDialog('route_include')"></el-button>
                </el-col>
              </el-row>
              <templete v-if="activeTab == 'route'">
                <el-row v-for="(item, index) in ruleForm.route_include" :key="index" style="margin-bottom: 5px"
                  :gutter="10">
                  <el-col :span="10">
                    <el-input v-model="item.val"></el-input>
                  </el-col>
                  <el-col :span="12">
                    <el-input v-model="item.note" placeholder="备注"></el-input>
                  </el-col>
                  <el-col :span="2">
                    <el-button size="mini" type="danger" icon="el-icon-minus" circle
                      @click.prevent="removeDomain(ruleForm.route_include, index)"></el-button>
                  </el-col>
                </el-row>
              </templete>
            </el-form-item>

            <el-form-item label="排除路由" prop="route_exclude">
              <el-row class="msg-info">
                <el-col :span="18">输入CIDR格式如: 192.168.2.0/24</el-col>
                <el-col :span="2">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.route_exclude)"></el-button>
                </el-col>
                <el-col :span="4">
                  <el-button size="mini" type="info" icon="el-icon-edit" circle
                    @click.prevent="openIpListDialog('route_exclude')"></el-button>
                </el-col>
              </el-row>
              <templete v-if="activeTab == 'route'">
                <el-row v-for="(item, index) in ruleForm.route_exclude" :key="index" style="margin-bottom: 5px"
                  :gutter="10">
                  <el-col :span="10">
                    <el-input v-model="item.val"></el-input>
                  </el-col>
                  <el-col :span="12">
                    <el-input v-model="item.note" placeholder="备注"></el-input>
                  </el-col>
                  <el-col :span="2">
                    <el-button size="mini" type="danger" icon="el-icon-minus" circle
                      @click.prevent="removeDomain(ruleForm.route_exclude, index)"></el-button>
                  </el-col>
                </el-row>
              </templete>
            </el-form-item>
          </el-tab-pane>
          <el-tab-pane label="权限控制" name="link_acl">
            <el-form-item label="权限控制" prop="link_acl">
              <el-row class="msg-info">
                <el-col :span="22">输入CIDR格式如: 192.168.3.0/24
                  协议支持 all,tcp,udp,icmp
                  端口0表示所有端口,多个端口:80,443,连续端口:1234-5678
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.link_acl)"></el-button>
                </el-col>
              </el-row>

              <!--  添加拖拽功能  -->
              <draggable v-model="ruleForm.link_acl" handle=".drag-handle" @end="onEnd">

                <el-row v-for="(item, index) in ruleForm.link_acl" :key="index" style="margin-bottom: 5px" :gutter="1">

                  <el-col :span="1" class="drag-handle">
                    <i class="el-icon-rank"></i>
                  </el-col>

                  <el-col :span="9">
                    <el-input placeholder="请输入CIDR地址" v-model="item.val">
                      <el-select v-model="item.action" slot="prepend">
                        <el-option label="允许" value="allow"></el-option>
                        <el-option label="禁止" value="deny"></el-option>
                      </el-select>
                    </el-input>
                  </el-col>

                  <el-col :span="3">
                    <el-input placeholder="协议" v-model="item.protocol"></el-input>
                  </el-col>

                  <el-col :span="6">
                    <!--  type="textarea" :autosize="{ minRows: 1, maxRows: 2}"  -->
                    <el-input v-model="item.port" placeholder="多端口,号分隔"></el-input>
                  </el-col>
                  <el-col :span="3">
                    <el-input v-model="item.note" placeholder="备注"></el-input>
                  </el-col>

                  <el-col :span="2">
                    <el-button size="mini" type="danger" icon="el-icon-minus" circle
                      @click.prevent="removeDomain(ruleForm.link_acl, index)"></el-button>
                  </el-col>
                </el-row>
              </draggable>

            </el-form-item>
          </el-tab-pane>

          <el-tab-pane label="域名拆分隧道" name="ds_domains">
            <el-form-item label="包含域名" prop="ds_include_domains">
              <el-input type="textarea" :rows="5" v-model="ruleForm.ds_include_domains"
                placeholder="输入域名用,号分隔，默认匹配所有子域名, 如baidu.com,163.com"></el-input>
            </el-form-item>
            <el-form-item label="排除域名" prop="ds_exclude_domains">
              <el-input type="textarea" :rows="5" v-model="ruleForm.ds_exclude_domains"
                placeholder="输入域名用,号分隔，默认匹配所有子域名, 如baidu.com,163.com"></el-input>
              <div class="msg-info">注：域名拆分隧道，仅支持AnyConnect的windows和MacOS桌面客户端，不支持移动端.</div>
            </el-form-item>
          </el-tab-pane>
          <el-form-item>
            <templete
              v-if="activeTab == 'authtype' && (ruleForm.auth.type == 'ldap' || ruleForm.auth.type == 'radius')">
              <el-button @click="openAuthLoginDialog()" style="margin-right:10px">测试登录</el-button>
            </templete>
            <el-button type="primary" :loading="groupSaving" :disabled="editLoading" @click="submitForm('ruleForm')">保存</el-button>
            <el-button :disabled="groupSaving" @click="closeDialog">取消</el-button>
            <templete v-if="activeTab == 'authtype' && ruleForm.auth.type == 'ldap'">
              <el-button type="success" @click="saveldapUsers" :loading="saveLoading"
                style="margin-left:10px">同步用户</el-button>
              <el-tooltip content="保存或更新LDAP用户到本地" placement="top">
                <i class="el-icon-info" style="margin-left: 10px; cursor: pointer; color: #888;"></i>
              </el-tooltip>
            </templete>
          </el-form-item>
        </el-tabs>
      </el-form>
    </el-dialog>
    <!--测试用户登录弹出框-->
    <el-dialog :close-on-click-modal="false" title="测试用户登录" :visible.sync="authLoginDialog" width="600px"
      custom-class="valgin-dialog" center>
      <el-form :model="authLoginForm" :rules="authLoginRules" ref="authLoginForm" label-width="100px">
        <el-form-item label="账号" prop="name">
          <el-input v-model="authLoginForm.name" ref="authLoginFormName"
            @keydown.enter.native="testAuthLogin"></el-input>
        </el-form-item>
        <el-form-item label="密码" prop="pwd">
          <el-input type="password" v-model="authLoginForm.pwd" @keydown.enter.native="testAuthLogin"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testAuthLogin()" :loading="authLoginLoading">登录</el-button>
          <el-button @click="authLoginDialog = false">取 消</el-button>
        </el-form-item>
      </el-form>
    </el-dialog>
    <!--编辑模式弹窗-->
    <el-dialog :close-on-click-modal="false" title="编辑模式" :visible.sync="ipListDialog" width="650px"
      custom-class="valgin-dialog" center>
      <el-form ref="ipEditForm" label-width="80px">
        <el-form-item label="路由表" prop="ip_list">
          <el-input type="textarea" :rows="10" v-model="ipEditForm.ip_list"
            placeholder="每行一条路由，例：192.168.1.0/24,备注 或 192.168.1.0/24"></el-input>
          <div class="msg-info">当前共
            {{ ipEditForm.ip_list.trim() === '' ? 0 : ipEditForm.ip_list.trim().split("\n").length }}
            条（注：AnyConnect客户端最多支持{{ this.maxRouteRows }}条路由）
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="ipEdit()" :loading="ipEditLoading">更新</el-button>
          <el-button @click="ipListDialog = false">取 消</el-button>
        </el-form-item>
      </el-form>
    </el-dialog>
  </div>
</template>

<script>
import axios from "axios";
import draggable from 'vuedraggable'

import SSOConfigForm from '@/components/SSOConfigForm.vue';
import { ssoDefaults } from '@/utils/ssoConfig';

function groupDefaults() {
  return {
    id: 0,
    name: '',
    note: '',
    bandwidth: 0,
    bandwidth_format: '0',
    status: 1,
    allow_lan: true,
    client_dns: [{ val: '114.114.114.114', note: '默认dns' }],
    split_dns: [],
    route_include: [{ val: 'all', note: '默认全局代理' }],
    route_exclude: [],
    link_acl: [],
    ds_include_domains: '',
    ds_exclude_domains: '',
    auth: {},
    auth_revision: '',
    sso_secret_set: false,
    sso_secret_action: 'preserve',
  };
}

export default {
  name: "List",
  components: { draggable, SSOConfigForm },
  mixins: [],
  created() {
    this.$emit('update:route_path', this.$route.path)
    this.$emit('update:route_name', ['用户组信息', '用户组列表'])
  },
  mounted() {
    this.getData(1);
    this.setAuthData();
  },
  computed: {
    isSSOAuth() {
      return ['oidc', 'oauth2'].includes(this.ruleForm.auth.type);
    },
    currentSSOConfig() {
      return this.ruleForm.auth[this.ruleForm.auth.type] || {};
    },
    ssoSecretSet() {
      if (!this.savedSSOSecretSet || this.ruleForm.auth.type !== this.savedSSOAuthType) return false;
      const fields = this.ruleForm.auth.type === 'oidc'
        ? ['issuer', 'client_id'] : ['authorization_url', 'token_url', 'userinfo_url', 'client_id'];
      return fields.every(field => (this.currentSSOConfig[field] || '') === (this.savedSSOConfig[field] || ''));
    },
  },
  data() {
    return {
      page: 1,
      tableData: [],
      count: 10,
      activeTab: "general",
      readMore: {},
      readMinRows: 5,
      maxRouteRows: 2500,
      defAuth: {
        type: 'local',
        radius: { addr: "", secret: "", nasip: "" },
        ldap: {
          addr: "",
          tls: false,
          base_dn: "",
          object_class: "person",
          search_attr: "sAMAccountName",
          member_of: "",
          bind_name: "",
          bind_pwd: "",
          enable_otp: false,
          sync_user_status: false,
        },
        wxwork: {
          corp_id: "",
          agent_id: "",
          secret: "",
          use_default_browser: false,
          allowed_departments: "",
        },
        oidc: ssoDefaults('oidc'),
        oauth2: ssoDefaults('oauth2'),
      },
      ruleForm: groupDefaults(),
      savedSSOAuthType: '',
      savedSSOConfig: {},
      savedSSOSecretSet: false,
      clearSSOSecret: false,
      editLoading: false,
      editRequestId: 0,
      groupSaving: false,
      authLoginDialog: false,
      saveLoading: false,
      ipListDialog: false,
      authLoginLoading: false,
      authLoginForm: {
        name: "",
        pwd: "",
      },
      ipEditForm: {
        ip_list: "",
        type: "",
      },
      ipEditLoading: false,
      authLoginRules: {
        name: [
          { required: true, message: '请输入账号', trigger: 'blur' },
        ],
        pwd: [
          { required: true, message: '请输入密码', trigger: 'blur' },
          { min: 6, message: '长度至少 6 个字符', trigger: 'blur' }
        ],
      },
      rules: {
        name: [
          { required: true, message: '请输入组名', trigger: 'blur' },
          { max: 30, message: '长度小于 30 个字符', trigger: 'blur' }
        ],
        bandwidth_format: [
          { required: true, message: '请输入带宽限制', trigger: 'blur' },
          { type: 'string', message: '带宽限制必须为数字值' }
        ],
        status: [
          { required: true }
        ],
        "auth.radius.addr": [
          { required: true, message: '请输入Radius服务器', trigger: 'blur' }
        ],
        "auth.radius.secret": [
          { required: true, message: '请输入Radius密钥', trigger: 'blur' }
        ],
        "auth.ldap.addr": [
          { required: true, message: '请输入服务器地址(含端口)', trigger: 'blur' }
        ],
        "auth.ldap.bind_name": [
          { required: true, message: '请输入管理员 DN', trigger: 'blur' }
        ],
        "auth.ldap.bind_pwd": [
          { required: true, message: '请输入管理员密码', trigger: 'blur' }
        ],
        "auth.ldap.base_dn": [
          { required: true, message: '请输入Base DN值', trigger: 'blur' }
        ],
        "auth.ldap.object_class": [
          { required: true, message: '请输入用户对象类', trigger: 'blur' }
        ],
        "auth.ldap.search_attr": [
          { required: true, message: '请输入用户唯一ID', trigger: 'blur' }
        ],
        'auth.wxwork.corp_id': [
          { required: true, message: '请输入企业ID', trigger: 'blur' },
        ],
        'auth.wxwork.agent_id': [
          { required: true, message: '请输入应用ID', trigger: 'blur' },
        ],
        'auth.wxwork.secret': [
          { required: true, message: '请输入应用Secret', trigger: 'blur' },
        ],
      },
    }
  },
  methods: {
    onEnd: function () {
      window.console.log("onEnd", this.ruleForm.link_acl);
    },
    setAuthData(row) {
      const defaults = JSON.parse(JSON.stringify(this.defAuth));
      const saved = row && row.auth ? JSON.parse(JSON.stringify(row.auth)) : {};
      const auth = Object.assign({}, defaults, saved);
      ['radius', 'ldap', 'wxwork', 'oidc', 'oauth2'].forEach(type => {
        auth[type] = Object.assign({}, defaults[type], saved[type] || {});
      });
      if (!auth.ldap.object_class) {
        auth.ldap.object_class = defaults.ldap.object_class;
      }
      this.ruleForm.auth = auth;
    },
    handleDel(row) {
      axios.post('/group/del?id=' + row.id).then(resp => {
        const rdata = resp.data;
        if (rdata.code === 0) {
          this.$message.success(rdata.msg);
          this.getData(1);
        } else {
          this.$message.error(rdata.msg);
        }
        console.log(rdata);
      }).catch(error => {
        this.$message.error('哦，请求出错');
        console.log(error);
      });
    },
    async handleEdit(row) {
      if (this.groupSaving) return;
      const requestId = ++this.editRequestId;
      // Start every create/edit operation with a fresh form. resetFields alone
      // retains unknown properties such as the previous id and auth revision.
      this.ruleForm = groupDefaults();
      this.setAuthData();
      this.savedSSOAuthType = '';
      this.savedSSOConfig = {};
      this.savedSSOSecretSet = false;
      this.clearSSOSecret = false;
      this.otpChanged = false;
      this.activeTab = 'general';
      this.editLoading = !!row;
      this.user_edit_dialog = true;
      await this.$nextTick();
      if (this.$refs.ruleForm) this.$refs.ruleForm.clearValidate();
      if (!row) return;
      try {
        const { data } = await axios.get('/group/detail', { params: { id: row.id } });
        if (requestId !== this.editRequestId || !this.user_edit_dialog) return;
        if (data.code !== 0 || !data.data) throw new Error(data.msg || '加载用户组失败');
        this.ruleForm = Object.assign(groupDefaults(), data.data);
        this.ruleForm.bandwidth_format = this.convertBandwidth(this.ruleForm.bandwidth, 'BYTE', 'Mbps').toString();
        this.setAuthData(data.data);
        this.savedSSOAuthType = this.ruleForm.auth.type;
        this.savedSSOConfig = JSON.parse(JSON.stringify(this.currentSSOConfig));
        this.savedSSOSecretSet = !!data.data.sso_secret_set;
      } catch (error) {
        if (requestId === this.editRequestId) {
          this.$message.error('加载用户组失败，请重新打开编辑。');
          this.user_edit_dialog = false;
        }
      } finally {
        if (requestId === this.editRequestId) this.editLoading = false;
      }
    },
    pageChange(p) {
      this.getData(p)
    },
    getData(page) {
      this.page = page
      axios.get('/group/list', {
        params: {
          page: page,
        }
      }).then(resp => {
        const rdata = resp.data.data;
        this.tableData = rdata.datas;
        this.count = rdata.count
      }).catch(error => {
        this.$message.error('哦，请求出错');
        console.log(error);
      });
    },
    removeDomain(arr, index) {
      console.log(index)
      if (index >= 0 && index < arr.length) {
        arr.splice(index, 1)
      }
      // let index = arr.indexOf(item);
      // if (index !== -1 && arr.length > 1) {
      //   arr.splice(index, 1)
      // }
      // arr.pop()
    },
    addDomain(arr) {
      console.log("arr", arr)
      arr.push({ protocol: "all", val: "", action: "allow", port: "0", note: "" });
    },
    handleOtpChange(newValue) {
      // 记录 OTP 状态变化 
      this.otpChanged = true;
      this.newOtpState = newValue;
    },
    async submitForm(formName) {
      if (this.groupSaving || this.editLoading) return;
      this.groupSaving = true;
      try {
        if (this.isSSOAuth && !(await this.$refs.ssoConfigForm.validate())) {
          this.activeTab = 'authtype';
          return;
        }
        if (this.isSSOAuth && this.savedSSOSecretSet && !this.ssoSecretSet &&
            !this.currentSSOConfig.client_secret && !this.clearSSOSecret) {
          this.activeTab = 'authtype';
          this.$message.error('身份平台或 Client ID 已变更，请填写新密钥，或选择公开客户端。');
          return;
        }
        const valid = await new Promise(resolve => this.$refs[formName].validate(resolve));
        if (!valid) return;
        this.ruleForm.sso_secret_action = this.isSSOAuth && this.currentSSOConfig.client_secret
          ? 'replace' : this.isSSOAuth && this.clearSSOSecret ? 'clear' : 'preserve';
        this.ruleForm.bandwidth = this.convertBandwidth(this.ruleForm.bandwidth_format, 'Mbps', 'BYTE');
        const { data } = await axios.post('/group/set', this.ruleForm, {
          headers: { 'Content-Type': 'application/json' },
        });
        if (data.code !== 0) {
          const messages = {
            sso_config_conflict: '认证配置已被其他页面修改，请重新打开编辑后再保存。',
            sso_provider_changed_secret_action_required: '身份平台已变更，请填写新密钥，或选择公开客户端。',
            sso_group_not_found: '此用户组已删除，请刷新用户组列表。',
            sso_secret_required: '请输入新的 Client Secret。',
          };
          this.$message.error(messages[data.msg] || data.msg || '保存失败，请重试。');
          return;
        }
        this.$message.success(data.msg);
        if (this.ruleForm.auth.type === 'ldap' && this.otpChanged) this.saveldapUsers();
        this.otpChanged = false;
        this.getData(1);
        this.user_edit_dialog = false;
      } catch (error) {
        // Axios errors may contain the submitted client secret in config.data.
        this.$message.error('保存失败，请稍后重试。');
      } finally {
        this.groupSaving = false;
      }
    },
    saveldapUsers() {
      this.saveLoading = true;
      axios.post('/group/saveldapusers', this.ruleForm).then(resp => {
        const rdata = resp.data;
        if (rdata.code === 0) {
          this.$message.success(rdata.data || '同步成功');
        } else {
          this.$message.error(rdata.msg);
        }
      }).catch(error => {
        this.$message.error('同步失败，请检查LDAP配置');
        console.log(error);
      }).finally(() => {
        this.saveLoading = false;
      });
    },
    testAuthLogin() {
      this.$refs["authLoginForm"].validate((valid) => {
        if (!valid) {
          console.log('error submit!!');
          return false;
        }
        this.authLoginLoading = true;
        axios.post('/group/auth_login', {
          name: this.authLoginForm.name,
          pwd: this.authLoginForm.pwd,
          auth: this.ruleForm.auth
        }).then(resp => {
          const rdata = resp.data;
          if (rdata.code === 0) {
            this.$message.success("登录成功");
          } else {
            this.$message.error(rdata.msg);
          }
          this.authLoginLoading = false;
          console.log(rdata);
        }).catch(error => {
          this.$message.error('哦，请求出错');
          console.log(error);
          this.authLoginLoading = false;
        });
      });
    },
    openAuthLoginDialog() {
      this.$refs["ruleForm"].validate((valid) => {
        if (!valid) {
          console.log('error submit!!');
          return false;
        }
        this.authLoginDialog = true;
        // set authLoginFormName focus
        this.$nextTick(() => {
          this.$refs['authLoginFormName'].focus();
        });
      });
    },
    openIpListDialog(type) {
      this.ipListDialog = true;
      this.ipEditForm.type = type;
      this.ipEditForm.ip_list = this.ruleForm[type].map(item => item.val + (item.note ? "," + item.note : "")).join("\n");
    },
    ipEdit() {
      this.ipEditLoading = true;
      let ipList = [];
      if (this.ipEditForm.ip_list.trim() !== "") {
        ipList = this.ipEditForm.ip_list.trim().split("\n");
      }
      let arr = [];
      for (let i = 0; i < ipList.length; i++) {
        let item = ipList[i];
        if (item.trim() === "") {
          continue;
        }
        let ip = item.split(",");
        if (ip.length > 2) {
          ip[1] = ip.slice(1).join(",");
        }
        let note = ip[1] ? ip[1] : "";
        const pushToArr = () => {
          arr.push({ val: ip[0], note: note });
        };
        if (this.ipEditForm.type == "route_include" && ip[0] == "all") {
          pushToArr();
          continue;
        }
        let valid = this.isValidCIDR(ip[0]);
        if (!valid.valid) {
          this.$message.error("错误：CIDR格式错误，建议 " + ip[0] + " 改为 " + valid.suggestion);
          this.ipEditLoading = false;
          return;
        }
        pushToArr();
      }
      this.ruleForm[this.ipEditForm.type] = arr;
      this.ipEditLoading = false;
      this.ipListDialog = false;
    },
    isValidCIDR(input) {
      const cidrRegex = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\/([12]?\d|3[0-2])$/;
      if (!cidrRegex.test(input)) {
        return { valid: false, suggestion: null };
      }
      const [ip, mask] = input.split('/');
      const maskNum = parseInt(mask);
      const ipParts = ip.split('.').map(part => parseInt(part));
      const binaryIP = ipParts.map(part => part.toString(2).padStart(8, '0')).join('');
      for (let i = maskNum; i < 32; i++) {
        if (binaryIP[i] === '1') {
          const binaryNetworkPart = binaryIP.substring(0, maskNum).padEnd(32, '0');
          const networkIPParts = [];
          for (let j = 0; j < 4; j++) {
            const octet = binaryNetworkPart.substring(j * 8, (j + 1) * 8);
            networkIPParts.push(parseInt(octet, 2));
          }
          const suggestedIP = networkIPParts.join('.');
          return { valid: false, suggestion: `${suggestedIP}/${mask}` };
        }
      }
      return { valid: true, suggestion: null };
    },
    resetForm(formName) {
      this.$refs[formName].resetFields();
    },
    toggleMore(id) {
      if (this.readMore[id]) {
        this.$set(this.readMore, id, false);
      } else {
        this.$set(this.readMore, id, true);
      }
    },
    authTypeChange() {
      this.clearSSOSecret = false;
      this.$refs['ruleForm'].clearValidate();
    },
    beforeTabLeave() {
      var isSwitch = true
      if (!this.user_edit_dialog) {
        return isSwitch;
      }
      this.$refs['ruleForm'].validate((valid) => {
        if (!valid) {
          this.$message.error("错误：您有必填项没有填写。")
          isSwitch = false;
          return false;
        }
      });
      return isSwitch;
    },
    closeDialog() {
      if (this.groupSaving) return;
      this.editRequestId++;
      this.editLoading = false;
      this.user_edit_dialog = false;
      this.activeTab = "general";
    },
    convertBandwidth(bandwidth, fromUnit, toUnit) {
      const units = {
        bps: 1,
        Kbps: 1000,
        Mbps: 1000000,
        Gbps: 1000000000,
        BYTE: 8,
      };
      const result = bandwidth * units[fromUnit] / units[toUnit];
      const fixedResult = result.toFixed(2);
      return parseFloat(fixedResult);
    }
  },
}
</script>

<style scoped>
.msg-info {
  background-color: #f4f4f5;
  color: #909399;
  padding: 0 5px;
  margin: 0;
  box-sizing: border-box;
  border-radius: 4px;
  font-size: 12px;
}

.el-select {
  width: 80px;
}

::v-deep .valgin-dialog {
  display: flex;
  flex-direction: column;
  margin: 0 !important;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  max-height: calc(100% - 30px);
  max-width: calc(100% - 30px);
}

::v-deep .valgin-dialog .el-dialog__body {
  flex: 1;
  overflow: auto;
}

.drag-handle {
  cursor: move;
}
</style>
