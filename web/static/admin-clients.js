const state = {
  csrf: document.querySelector('meta[name="csrf-token"]')?.content || "",
  adminPermissions: new Set(
    (document.querySelector('meta[name="admin-permissions"]')?.content || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  ),
  adminRoleDefinitions: [],
  clients: [],
  users: [],
  allUsers: [],
  keys: [],
  roles: [],
  permissions: [],
  userRoleAssignments: [],
  userOffset: 0,
  userTotal: 0,
  auditOffset: 0,
  auditTotal: 0,
};

const globalStatus = document.querySelector("#global-status");
const userForm = document.querySelector("#user-form");
const clientForm = document.querySelector("#client-form");
const integrationCard = document.querySelector("#integration-card");
const integrationOutput = document.querySelector("#integration-output");
const secretWarning = document.querySelector("#secret-warning");

function element(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (name === "className") {
      node.className = value;
    } else if (name === "text") {
      node.textContent = value;
    } else if (name === "dataset") {
      Object.assign(node.dataset, value);
    } else {
      node.setAttribute(name, value);
    }
  }
  for (const child of children) {
    node.append(child);
  }
  return node;
}

function button(label, action, value, className = "secondary") {
  const node = element("button", { type: "button", className, text: label, dataset: { action } });
  if (value !== undefined) {
    node.dataset.value = value;
  }
  return node;
}

function setStatus(message, kind = "") {
  globalStatus.textContent = message;
  globalStatus.className = `console-status ${kind}`.trim();
}

function formatDate(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN");
}

function statusBadge(label, kind) {
  return element("span", { className: `badge ${kind}`, text: label });
}

function emptyRow(columns, message) {
  const cell = element("td", { colspan: String(columns), className: "empty", text: message });
  return element("tr", {}, [cell]);
}

function lines(value) {
  return String(value || "").split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

function words(value) {
  return String(value || "").split(/\s+/).map((item) => item.trim()).filter(Boolean);
}

function checkedValues(form, name) {
  return [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((input) => input.value);
}

function setCheckedValues(form, name, values) {
  const selected = new Set(values || []);
  for (const input of form.querySelectorAll(`input[name="${name}"]`)) {
    input.checked = selected.has(input.value);
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const method = String(options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", state.csrf);
  }
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const raw = await response.text();
  let body = null;
  if (raw) {
    try {
      body = JSON.parse(raw);
    } catch {
      body = { detail: raw };
    }
  }
  if (!response.ok) {
    if (response.status === 401) {
      window.location.assign(`/login?continue=${encodeURIComponent("/admin")}`);
      throw new Error("管理员会话已失效，正在重新登录");
    }
    if (response.status === 403 && body?.code === "admin_mfa_required") {
      window.location.assign("/account?admin_mfa=required");
      throw new Error("管理员操作要求多因素认证");
    }
    throw new Error(body?.detail || body?.title || `请求失败（${response.status}）`);
  }
  return body;
}

function can(permission) {
  return state.adminPermissions.has("*") || state.adminPermissions.has(permission);
}

function applyPermissions() {
  const sectionPermissions = {
    users: "admin.users.read",
    clients: "admin.clients.read",
    access: "admin.access.read",
    audit: "admin.audit.read",
    operations: "admin.security.read",
  };
  for (const link of document.querySelectorAll("#console-nav a[data-section]")) {
    const permission = sectionPermissions[link.dataset.section];
    link.classList.toggle("hidden", Boolean(permission) && !can(permission));
  }
  const visibility = [
    ["#new-user", "admin.users.write"],
    ["#user-form button[type='submit']", "admin.users.write"],
    ["#user-password-form", "admin.users.write"],
    ["#issue-reset", "admin.users.write"],
    ["#revoke-user-sessions", "admin.users.write"],
    ["#reset-user-mfa", "admin.users.write"],
    ["#new-client", "admin.clients.write"],
    ["#role-form", "admin.access.write"],
    ["#permission-form", "admin.access.write"],
    ["#role-permission-form button[type='submit']", "admin.access.write"],
    ["#user-role-form button[type='submit']", "admin.access.write"],
    ["#rotate-signing-key", "admin.security.write"],
    ["#run-cleanup", "admin.maintenance.execute"],
  ];
  for (const [selector, permission] of visibility) {
    const target = document.querySelector(selector);
    if (target) target.classList.toggle("hidden", !can(permission));
  }
  const userFieldsReadOnly = !can("admin.users.write");
  for (const field of userForm.elements) {
    if (field.type !== "hidden") field.disabled = userFieldsReadOnly;
  }
  const clientFieldsReadOnly = !can("admin.clients.write");
  for (const field of clientForm.elements) {
    field.disabled = clientFieldsReadOnly;
  }
}

function activateSection(name) {
  const available = new Set(["overview", "users", "clients", "access", "audit", "operations"]);
  const required = {
    users: "admin.users.read",
    clients: "admin.clients.read",
    access: "admin.access.read",
    audit: "admin.audit.read",
    operations: "admin.security.read",
  };
  let target = available.has(name) ? name : "overview";
  if (required[target] && !can(required[target])) target = "overview";
  for (const section of document.querySelectorAll(".console-section")) {
    section.classList.toggle("hidden", section.id !== target);
  }
  for (const link of document.querySelectorAll("#console-nav a")) {
    link.classList.toggle("active", link.dataset.section === target);
  }
}

window.addEventListener("hashchange", () => {
  const section = location.hash.slice(1);
  activateSection(section);
  refreshSection(section);
});

function refreshSection(name) {
  let task;
  switch (name) {
    case "users":
      if (!can("admin.users.read")) return;
      task = Promise.all([loadUsers(), loadAllUsers()]);
      break;
    case "clients":
      if (!can("admin.clients.read")) return;
      task = loadClients();
      break;
    case "access": {
      if (!can("admin.access.read")) return;
      const clientID = document.querySelector("#access-client").value;
      task = clientID ? loadAccessData(clientID) : loadClients();
      break;
    }
    case "audit":
      if (!can("admin.audit.read")) return;
      task = loadAudit();
      break;
    case "operations":
      if (!can("admin.security.read")) return;
      task = loadKeys();
      break;
    case "overview":
      task = refreshAll();
      break;
    default:
      return;
  }
  task.catch((error) => setStatus(error.message, "error"));
}

function clearConsole() {
  state.clients = [];
  state.users = [];
  state.allUsers = [];
  state.keys = [];
  state.roles = [];
  state.permissions = [];
  document.querySelector("#metric-users").textContent = "—";
  document.querySelector("#metric-clients").textContent = "—";
  document.querySelector("#metric-active-clients").textContent = "—";
  document.querySelector("#metric-keys").textContent = "—";
  document.querySelector("#user-rows").replaceChildren(emptyRow(5, "当前角色无权读取用户"));
  document.querySelector("#client-rows").replaceChildren(emptyRow(5, "当前角色无权读取接入系统"));
  document.querySelector("#audit-rows").replaceChildren(emptyRow(5, "当前角色无权读取审计日志"));
  document.querySelector("#signing-key-list").replaceChildren(element("p", { className: "empty", text: "当前角色无权读取签名密钥" }));
}

async function refreshAll() {
  setStatus("正在加载管理数据…");
  try {
    const tasks = [];
    if (can("admin.users.read")) tasks.push(loadUsers(), loadAllUsers());
    if (can("admin.clients.read")) tasks.push(loadClients());
    if (can("admin.security.read")) tasks.push(loadKeys());
    if (can("admin.audit.read")) tasks.push(loadAudit());
    if (can("admin.roles.read")) tasks.push(loadAdminRoleDefinitions());
    await Promise.all(tasks);
    setStatus("管理数据已更新。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

document.querySelector('[data-action="refresh-all"]').addEventListener("click", refreshAll);

async function loadUsers() {
  const filter = new FormData(document.querySelector("#user-filter"));
  const params = new URLSearchParams({ limit: "20", offset: String(state.userOffset) });
  if (filter.get("q")) params.set("q", filter.get("q"));
  if (filter.get("status")) params.set("status", filter.get("status"));
  const page = await api(`/api/v1/admin/users?${params}`);
  state.users = page.items || [];
  state.userTotal = page.total || 0;
  renderUsers();
  document.querySelector("#metric-users").textContent = String(state.userTotal);
}

async function loadAllUsers() {
  const page = await api("/api/v1/admin/users?limit=100&offset=0");
  state.allUsers = page.items || [];
  const select = document.querySelector("#access-user");
  const selected = select.value;
  select.replaceChildren(element("option", { value: "", text: "选择用户" }));
  for (const user of state.allUsers) {
    select.append(element("option", { value: user.id, text: `${user.display_name}（${user.username}）` }));
  }
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
}

function renderUsers() {
  const rows = document.querySelector("#user-rows");
  rows.replaceChildren();
  if (!state.users.length) rows.append(emptyRow(5, "没有匹配的用户"));
  for (const user of state.users) {
    const identity = element("div", { className: "table-primary" }, [
      element("strong", { text: user.display_name }),
      element("small", { text: `${user.username} · ${user.id}` }),
    ]);
    const label = user.status === "active" ? "正常" : user.status === "locked" ? "锁定" : "停用";
    const actions = element("div", { className: "row-actions" }, [button("管理", "edit-user", user.id)]);
    rows.append(element("tr", {}, [
      element("td", {}, [identity]),
      element("td", { text: user.email || "—" }),
      element("td", {}, [statusBadge(label, user.status)]),
      element("td", { text: formatDate(user.updated_at) }),
      element("td", {}, [actions]),
    ]));
  }
  const start = state.userTotal ? state.userOffset + 1 : 0;
  const end = Math.min(state.userOffset + state.users.length, state.userTotal);
  document.querySelector("#users-page").textContent = `${start}–${end} / ${state.userTotal}`;
  document.querySelector("#users-prev").disabled = state.userOffset === 0;
  document.querySelector("#users-next").disabled = state.userOffset + state.users.length >= state.userTotal;
}

async function loadAdminRoleDefinitions() {
  const value = await api("/api/v1/admin/roles");
  state.adminRoleDefinitions = value.items || [];
}

async function loadUserAdminRoles(userID) {
  const form = document.querySelector("#user-admin-role-form");
  if (!can("admin.roles.read")) {
    form.classList.add("hidden");
    return;
  }
  if (!state.adminRoleDefinitions.length) {
    await loadAdminRoleDefinitions();
  }
  const value = await api(`/api/v1/admin/users/${userID}/admin-roles`);
  const selected = new Set((value.items || []).map((item) => item.role));
  const options = document.querySelector("#user-admin-role-options");
  options.replaceChildren();
  for (const definition of state.adminRoleDefinitions) {
    const checkbox = element("input", { type: "checkbox", name: "roles", value: definition.code });
    checkbox.checked = selected.has(definition.code);
    checkbox.disabled = !can("admin.roles.write");
    options.append(element("label", { className: "check" }, [
      checkbox,
      element("span", {}, [
        element("strong", { text: definition.name }),
        element("small", { text: definition.description }),
      ]),
    ]));
  }
  form.querySelector("button[type='submit']").classList.toggle("hidden", !can("admin.roles.write"));
  form.classList.remove("hidden");
}

document.querySelector("#user-filter").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.userOffset = 0;
  try {
    await loadUsers();
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#users-prev").addEventListener("click", async () => {
  state.userOffset = Math.max(0, state.userOffset - 20);
  await loadUsers().catch((error) => setStatus(error.message, "error"));
});

document.querySelector("#users-next").addEventListener("click", async () => {
  state.userOffset += 20;
  await loadUsers().catch((error) => setStatus(error.message, "error"));
});

function openNewUser() {
  userForm.reset();
  userForm.elements.user_id.value = "";
  userForm.elements.username.readOnly = false;
  document.querySelector("#user-editor-title").textContent = "新建用户";
  document.querySelector("#user-security").classList.add("hidden");
  document.querySelector("#user-admin-role-form").classList.add("hidden");
  document.querySelector("#user-security-output").classList.add("hidden");
  document.querySelector("#user-editor").classList.remove("hidden");
  document.querySelector("#user-editor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function openUser(user) {
  userForm.reset();
  document.querySelector("#user-admin-role-form").classList.add("hidden");
  userForm.elements.user_id.value = user.id;
  userForm.elements.username.value = user.username;
  userForm.elements.username.readOnly = true;
  userForm.elements.display_name.value = user.display_name;
  userForm.elements.email.value = user.email || "";
  userForm.elements.status.value = user.status;
  document.querySelector("#user-editor-title").textContent = `${user.display_name} · ${user.username}`;
  document.querySelector("#user-security").classList.remove("hidden");
  document.querySelector("#user-security-output").classList.add("hidden");
  document.querySelector("#user-editor").classList.remove("hidden");
  document.querySelector("#user-editor").scrollIntoView({ behavior: "smooth", block: "start" });
  loadUserAdminRoles(user.id).catch((error) => setStatus(error.message, "error"));
}

document.querySelector("#new-user").addEventListener("click", openNewUser);
document.querySelector('[data-action="close-user"]').addEventListener("click", () => document.querySelector("#user-editor").classList.add("hidden"));

userForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(userForm);
  const userID = data.get("user_id");
  const payload = {
    display_name: data.get("display_name"),
    email: data.get("email") || null,
    status: data.get("status"),
  };
  if (!userID) payload.username = data.get("username");
  const status = document.querySelector("#user-form-status");
  status.textContent = "正在保存…";
  try {
    const user = await api(userID ? `/api/v1/admin/users/${userID}` : "/api/v1/admin/users", {
      method: userID ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    status.textContent = "已保存";
    await Promise.all([loadUsers(), loadAllUsers()]);
    openUser(user);
  } catch (error) {
    status.textContent = error.message;
  }
});

document.querySelector("#user-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const userID = userForm.elements.user_id.value;
  if (!window.confirm("设置新密码将撤销该用户的全部登录会话，确定继续吗？")) return;
  const data = new FormData(form);
  try {
    await api(`/api/v1/admin/users/${userID}/password`, { method: "PUT", body: JSON.stringify({ password: data.get("password") }) });
    form.reset();
    setStatus("密码已更新，用户现有会话已撤销。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

function showUserSecurity(value) {
  const output = document.querySelector("#user-security-output");
  output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  output.classList.remove("hidden");
}

document.querySelector("#issue-reset").addEventListener("click", async () => {
  try {
    const value = await api(`/api/v1/admin/users/${userForm.elements.user_id.value}/password-reset`, { method: "POST" });
    showUserSecurity(value);
    setStatus("一次性重置凭据已签发，有效期 30 分钟。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#list-user-sessions").addEventListener("click", async () => {
  try {
    const value = await api(`/api/v1/admin/users/${userForm.elements.user_id.value}/sessions`);
    showUserSecurity(value.items?.length ? value : "该用户当前没有有效会话。");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#revoke-user-sessions").addEventListener("click", async () => {
  if (!window.confirm("确定撤销该用户的全部登录会话吗？")) return;
  try {
    const value = await api(`/api/v1/admin/users/${userForm.elements.user_id.value}/sessions`, { method: "DELETE" });
    showUserSecurity(value);
    setStatus("用户会话已全部撤销。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#reset-user-mfa").addEventListener("click", async () => {
  if (!window.confirm("重置 MFA 会同时撤销该用户全部会话，确定继续吗？")) return;
  try {
    await api(`/api/v1/admin/users/${userForm.elements.user_id.value}/mfa`, { method: "DELETE" });
    showUserSecurity("MFA 已重置，用户全部会话已撤销。");
    setStatus("用户 MFA 已重置。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#user-admin-role-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!can("admin.roles.write")) return;
  const userID = userForm.elements.user_id.value;
  const roles = checkedValues(event.currentTarget, "roles");
  if (!window.confirm("管理员角色会立即影响该用户的后台权限，确定保存吗？")) return;
  try {
    await api(`/api/v1/admin/users/${userID}/admin-roles`, {
      method: "PUT",
      body: JSON.stringify({ roles }),
    });
    await loadUserAdminRoles(userID);
    setStatus("管理员角色已更新。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

async function loadClients() {
  const value = await api("/api/v1/admin/clients");
  state.clients = value.items || [];
  renderClients();
  renderClientSelectors();
  const available = state.clients.filter((item) => !item.archived_at);
  document.querySelector("#metric-clients").textContent = String(available.length);
  document.querySelector("#metric-active-clients").textContent = String(available.filter((item) => item.enabled).length);
}

function renderClients() {
  const rows = document.querySelector("#client-rows");
  rows.replaceChildren();
  if (!state.clients.length) rows.append(emptyRow(5, "尚未配置接入系统"));
  for (const client of state.clients) {
    const identity = element("div", { className: "table-primary" }, [
      element("strong", { text: client.name }),
      element("small", { text: client.id }),
    ]);
    const kind = client.archived_at ? "archived" : client.enabled ? "active" : "disabled";
    const label = client.archived_at ? "已归档" : client.enabled ? "启用" : "停用";
    const actions = element("div", { className: "row-actions" }, [
      button(client.archived_at ? "查看" : "管理", "edit-client", client.id),
      button("接入参数", "show-integration", client.id),
    ]);
    rows.append(element("tr", {}, [
      element("td", {}, [identity]),
      element("td", { text: client.application_type }),
      element("td", { text: (client.protocols || []).join(" · ") }),
      element("td", {}, [statusBadge(label, kind)]),
      element("td", {}, [actions]),
    ]));
  }
}

function renderClientSelectors() {
  const select = document.querySelector("#access-client");
  const selected = select.value;
  select.replaceChildren(element("option", { value: "", text: "选择接入系统" }));
  for (const client of state.clients.filter((item) => !item.archived_at)) {
    select.append(element("option", { value: client.id, text: client.name }));
  }
  if (selected && [...select.options].some((option) => option.value === selected)) {
    select.value = selected;
  } else if (select.options.length > 1) {
    select.selectedIndex = 1;
  }
  if (select.value) loadAccessData(select.value).catch((error) => setStatus(error.message, "error"));
}

function resetClientForm() {
  clientForm.reset();
  for (const field of clientForm.elements) {
    field.disabled = !can("admin.clients.write");
  }
  clientForm.elements.id.readOnly = false;
  clientForm.elements.application_type.disabled = !can("admin.clients.write");
  clientForm.elements.allowed_scopes.value = "openid profile email";
  clientForm.elements.enabled.checked = true;
  setCheckedValues(clientForm, "protocols", ["oauth2.1"]);
  setCheckedValues(clientForm, "grant_types", ["authorization_code", "refresh_token"]);
  setCheckedValues(clientForm, "login_methods", ["password"]);
  document.querySelector("#client-editor-title").textContent = "配置跳转登录";
  document.querySelector("#rotate-client-secret").classList.add("hidden");
  document.querySelector("#archive-client").classList.add("hidden");
  document.querySelector("#client-form-status").textContent = "";
}

function openNewClient() {
  resetClientForm();
  document.querySelector("#client-editor").classList.remove("hidden");
  document.querySelector("#client-editor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function openClient(client) {
  resetClientForm();
  clientForm.elements.id.value = client.id;
  clientForm.elements.id.readOnly = true;
  clientForm.elements.name.value = client.name;
  clientForm.elements.description.value = client.description || "";
  clientForm.elements.application_type.value = client.application_type;
  clientForm.elements.application_type.disabled = true;
  clientForm.elements.allowed_scopes.value = (client.allowed_scopes || []).join(" ");
  clientForm.elements.redirect_uris.value = (client.redirect_uris || []).join("\n");
  clientForm.elements.post_logout_redirect_uris.value = (client.post_logout_redirect_uris || []).join("\n");
  clientForm.elements.backchannel_logout_uri.value = client.backchannel_logout_uri || "";
  clientForm.elements.backchannel_logout_session_required.checked = Boolean(client.backchannel_logout_session_required);
  clientForm.elements.cas_version.value = client.cas_version || "3.0";
  clientForm.elements.cas_service_urls.value = (client.cas_service_urls || []).join("\n");
  clientForm.elements.cas_proxy.checked = Boolean(client.cas_proxy);
  clientForm.elements.cas_gateway.checked = Boolean(client.cas_gateway);
  clientForm.elements.cas_renew.checked = Boolean(client.cas_renew);
  clientForm.elements.cas_single_logout.checked = Boolean(client.cas_single_logout);
  clientForm.elements.enabled.checked = Boolean(client.enabled);
  setCheckedValues(clientForm, "protocols", client.protocols);
  setCheckedValues(clientForm, "grant_types", client.grant_types);
  setCheckedValues(clientForm, "login_methods", client.login_methods);
  const archived = Boolean(client.archived_at);
  for (const field of clientForm.elements) field.disabled = archived || !can("admin.clients.write");
  document.querySelector("#client-editor-title").textContent = `${client.name} · ${client.id}`;
  document.querySelector("#rotate-client-secret").classList.toggle(
    "hidden",
    archived || client.application_type !== "confidential" || !can("admin.clients.write"),
  );
  document.querySelector("#archive-client").classList.toggle(
    "hidden",
    archived || !can("admin.clients.write"),
  );
  document.querySelector("#client-editor").classList.remove("hidden");
  document.querySelector("#client-editor").scrollIntoView({ behavior: "smooth", block: "start" });
}

document.querySelector("#new-client").addEventListener("click", openNewClient);
document.querySelector('[data-action="close-client"]').addEventListener("click", () => document.querySelector("#client-editor").classList.add("hidden"));

clientForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(clientForm);
  const existing = state.clients.find((item) => item.id === data.get("id"));
  const payload = {
    name: data.get("name"),
    description: data.get("description"),
    protocols: data.getAll("protocols"),
    grant_types: data.getAll("grant_types"),
    redirect_uris: lines(data.get("redirect_uris")),
    post_logout_redirect_uris: lines(data.get("post_logout_redirect_uris")),
    backchannel_logout_uri: data.get("backchannel_logout_uri"),
    backchannel_logout_session_required: data.has("backchannel_logout_session_required"),
    login_methods: data.getAll("login_methods"),
    allowed_scopes: words(data.get("allowed_scopes")),
    cas_version: data.get("cas_version"),
    cas_service_urls: lines(data.get("cas_service_urls")),
    cas_proxy: data.has("cas_proxy"),
    cas_gateway: data.has("cas_gateway"),
    cas_renew: data.has("cas_renew"),
    cas_single_logout: data.has("cas_single_logout"),
    enabled: data.has("enabled"),
  };
  if (!existing) {
    payload.id = data.get("id");
    payload.application_type = data.get("application_type");
  }
  const status = document.querySelector("#client-form-status");
  status.textContent = "正在保存…";
  try {
    const value = await api(existing ? `/api/v1/admin/clients/${existing.id}` : "/api/v1/admin/clients", {
      method: existing ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    status.textContent = "已保存";
    showIntegration(value.integration);
    await loadClients();
    openClient(value.client);
  } catch (error) {
    status.textContent = error.message;
  }
});

function showIntegration(value) {
  integrationOutput.textContent = JSON.stringify(value, null, 2);
  secretWarning.classList.toggle("hidden", !value?.client_secret);
  integrationCard.classList.remove("hidden");
  integrationCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.querySelector("#copy-integration").addEventListener("click", async (event) => {
  const copyButton = event.currentTarget;
  try {
    await navigator.clipboard.writeText(integrationOutput.textContent);
    copyButton.textContent = "已复制";
    setTimeout(() => { copyButton.textContent = "复制参数"; }, 1500);
  } catch {
    setStatus("浏览器未允许访问剪贴板，请手动复制。", "error");
  }
});

document.querySelector("#rotate-client-secret").addEventListener("click", async () => {
  const clientID = clientForm.elements.id.value;
  if (!window.confirm(`轮换 ${clientID} 的密钥后旧密钥立即失效，确定继续吗？`)) return;
  try {
    const value = await api(`/api/v1/admin/clients/${clientID}/secret`, { method: "POST" });
    showIntegration(value.integration);
    setStatus("客户端密钥已轮换，请立即保存新密钥。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#archive-client").addEventListener("click", async () => {
  const clientID = clientForm.elements.id.value;
  if (!window.confirm(`归档 ${clientID} 后不能恢复或修改，确定继续吗？`)) return;
  try {
    await api(`/api/v1/admin/clients/${clientID}`, { method: "DELETE" });
    document.querySelector("#client-editor").classList.add("hidden");
    await loadClients();
    setStatus("接入系统已归档。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

async function loadAccessData(clientID) {
  if (!clientID) {
    state.roles = [];
    state.permissions = [];
    renderAccessDefinitions();
    return;
  }
  const [rolePage, permissionPage] = await Promise.all([
    api(`/api/v1/admin/clients/${clientID}/roles`),
    api(`/api/v1/admin/clients/${clientID}/permissions`),
  ]);
  state.roles = rolePage.items || [];
  state.permissions = permissionPage.items || [];
  renderAccessDefinitions();
  await loadRolePermissions();
  await loadUserRoles();
}

function definitionItem(value) {
  return element("div", { className: "compact-item" }, [
    element("div", {}, [element("strong", { text: value.name }), element("small", { text: value.code })]),
    element("small", { text: value.description || value.id }),
  ]);
}

function renderAccessDefinitions() {
  const roleList = document.querySelector("#role-list");
  roleList.replaceChildren(...(state.roles.length ? state.roles.map(definitionItem) : [element("p", { className: "empty", text: "尚未创建角色" })]));
  const permissionList = document.querySelector("#permission-list");
  permissionList.replaceChildren(...(state.permissions.length ? state.permissions.map(definitionItem) : [element("p", { className: "empty", text: "尚未创建权限点" })]));

  const roleSelect = document.querySelector("#permission-role");
  const selected = roleSelect.value;
  roleSelect.replaceChildren(element("option", { value: "", text: "选择角色" }));
  for (const role of state.roles) roleSelect.append(element("option", { value: role.id, text: `${role.name}（${role.code}）` }));
  if (selected && [...roleSelect.options].some((option) => option.value === selected)) {
    roleSelect.value = selected;
  } else if (roleSelect.options.length > 1) {
    roleSelect.selectedIndex = 1;
  }

  const options = document.querySelector("#role-permission-options");
  options.replaceChildren();
  for (const permission of state.permissions) {
    const input = element("input", { type: "checkbox", name: "permission_ids", value: permission.id });
    options.append(element("label", { className: "check" }, [input, document.createTextNode(`${permission.name}（${permission.code}）`)]));
  }
  if (!state.permissions.length) options.append(element("p", { className: "empty", text: "请先创建权限点" }));

  const userOptions = document.querySelector("#user-role-options");
  userOptions.replaceChildren();
  for (const role of state.roles) {
    const input = element("input", { type: "checkbox", name: "role_ids", value: role.id });
    userOptions.append(element("label", { className: "check" }, [input, document.createTextNode(`${role.name}（${role.code}）`)]));
  }
  if (!state.roles.length) userOptions.append(element("p", { className: "empty", text: "请先创建角色" }));
}

document.querySelector("#access-client").addEventListener("change", (event) => {
  loadAccessData(event.currentTarget.value).catch((error) => setStatus(error.message, "error"));
});

async function createDefinition(event, type) {
  event.preventDefault();
  const form = event.currentTarget;
  const clientID = document.querySelector("#access-client").value;
  if (!clientID) {
    setStatus("请先选择接入系统。", "error");
    return;
  }
  const data = new FormData(form);
  const payload = { code: data.get("code"), name: data.get("name"), description: data.get("description") };
  try {
    await api(`/api/v1/admin/clients/${clientID}/${type}`, { method: "POST", body: JSON.stringify(payload) });
    form.reset();
    await loadAccessData(clientID);
    setStatus(type === "roles" ? "角色已创建。" : "权限点已创建。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

document.querySelector("#role-form").addEventListener("submit", (event) => createDefinition(event, "roles"));
document.querySelector("#permission-form").addEventListener("submit", (event) => createDefinition(event, "permissions"));
document.querySelector("#permission-role").addEventListener("change", () => loadRolePermissions().catch((error) => setStatus(error.message, "error")));

async function loadRolePermissions() {
  const clientID = document.querySelector("#access-client").value;
  const roleID = document.querySelector("#permission-role").value;
  const form = document.querySelector("#role-permission-form");
  setCheckedValues(form, "permission_ids", []);
  if (!clientID || !roleID) return;
  const value = await api(`/api/v1/admin/clients/${clientID}/roles/${roleID}/permissions`);
  setCheckedValues(form, "permission_ids", (value.items || []).map((item) => item.id));
}

document.querySelector("#role-permission-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const clientID = document.querySelector("#access-client").value;
  const roleID = document.querySelector("#permission-role").value;
  if (!clientID || !roleID) {
    setStatus("请选择接入系统和角色。", "error");
    return;
  }
  try {
    await api(`/api/v1/admin/clients/${clientID}/roles/${roleID}/permissions`, {
      method: "PUT",
      body: JSON.stringify({ permission_ids: checkedValues(event.currentTarget, "permission_ids") }),
    });
    setStatus("角色权限映射已更新。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#access-user").addEventListener("change", () => loadUserRoles().catch((error) => setStatus(error.message, "error")));

async function loadUserRoles() {
  const userID = document.querySelector("#access-user").value;
  const form = document.querySelector("#user-role-form");
  setCheckedValues(form, "role_ids", []);
  state.userRoleAssignments = [];
  if (!userID) return;
  const value = await api(`/api/v1/admin/users/${userID}/roles?include_expired=true`);
  state.userRoleAssignments = value.items || [];
  const clientID = document.querySelector("#access-client").value;
  setCheckedValues(form, "role_ids", state.userRoleAssignments.filter((item) => item.role.client_id === clientID).map((item) => item.role.id));
}

document.querySelector("#user-role-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const userID = document.querySelector("#access-user").value;
  const clientID = document.querySelector("#access-client").value;
  if (!userID || !clientID) {
    setStatus("请选择接入系统和用户。", "error");
    return;
  }
  const selected = new Set(checkedValues(event.currentTarget, "role_ids"));
  const preserved = state.userRoleAssignments
    .filter((item) => item.role.client_id !== clientID)
    .map((item) => ({ role_id: item.role.id, ...(item.expires_at ? { expires_at: item.expires_at } : {}) }));
  for (const role of state.roles) {
    if (!selected.has(role.id)) continue;
    const current = state.userRoleAssignments.find((item) => item.role.id === role.id);
    preserved.push({ role_id: role.id, ...(current?.expires_at ? { expires_at: current.expires_at } : {}) });
  }
  try {
    await api(`/api/v1/admin/users/${userID}/roles`, { method: "PUT", body: JSON.stringify({ roles: preserved }) });
    await loadUserRoles();
    setStatus("用户角色已更新，其他接入系统的角色保持不变。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

async function loadAudit() {
  const data = new FormData(document.querySelector("#audit-filter"));
  const params = new URLSearchParams({ limit: "50", offset: String(state.auditOffset) });
  for (const name of ["event_type", "client_id", "actor_user_id", "outcome"]) {
    if (data.get(name)) params.set(name, data.get(name));
  }
  const page = await api(`/api/v1/admin/audit-events?${params}`);
  state.auditTotal = page.total || 0;
  const rows = document.querySelector("#audit-rows");
  rows.replaceChildren();
  if (!page.items?.length) rows.append(emptyRow(5, "没有匹配的审计事件"));
  for (const item of page.items || []) {
    const actor = item.actor_user_id || item.client_id || "系统";
    rows.append(element("tr", {}, [
      element("td", { text: formatDate(item.occurred_at) }),
      element("td", { text: item.event_type }),
      element("td", {}, [statusBadge(item.outcome === "success" ? "成功" : "失败", item.outcome)]),
      element("td", { text: actor }),
      element("td", {}, [element("code", { text: JSON.stringify(item.details || {}) })]),
    ]));
  }
  const start = state.auditTotal ? state.auditOffset + 1 : 0;
  const end = Math.min(state.auditOffset + (page.items?.length || 0), state.auditTotal);
  document.querySelector("#audit-page").textContent = `${start}–${end} / ${state.auditTotal}`;
  document.querySelector("#audit-prev").disabled = state.auditOffset === 0;
  document.querySelector("#audit-next").disabled = state.auditOffset + (page.items?.length || 0) >= state.auditTotal;
}

document.querySelector("#audit-filter").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.auditOffset = 0;
  await loadAudit().catch((error) => setStatus(error.message, "error"));
});
document.querySelector("#audit-prev").addEventListener("click", async () => {
  state.auditOffset = Math.max(0, state.auditOffset - 50);
  await loadAudit().catch((error) => setStatus(error.message, "error"));
});
document.querySelector("#audit-next").addEventListener("click", async () => {
  state.auditOffset += 50;
  await loadAudit().catch((error) => setStatus(error.message, "error"));
});

async function loadKeys() {
  const value = await api("/api/v1/admin/signing-keys");
  state.keys = value.items || [];
  document.querySelector("#metric-keys").textContent = String(state.keys.length);
  renderKeys(document.querySelector("#signing-key-list"));
  renderKeys(document.querySelector("#overview-keys"));
}

function renderKeys(target) {
  target.replaceChildren();
  if (!state.keys.length) {
    target.append(element("p", { className: "empty", text: "没有签名密钥" }));
    return;
  }
  for (const key of state.keys) {
    target.append(element("div", { className: "compact-item" }, [
      element("div", {}, [element("strong", { text: key.kid }), statusBadge(key.active ? "当前" : "已退役", key.active ? "active" : "archived")]),
      element("small", { text: key.retired_at ? `退役于 ${formatDate(key.retired_at)}` : `创建于 ${formatDate(key.created_at)}` }),
    ]));
  }
}

document.querySelector("#rotate-signing-key").addEventListener("click", async () => {
  if (!window.confirm("轮换 OIDC 签名密钥会影响所有新签发令牌，确定继续吗？")) return;
  try {
    const value = await api("/api/v1/admin/signing-keys/rotate", { method: "POST" });
    await loadKeys();
    setStatus(`签名密钥已轮换，新 KID：${value.kid}`, "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#run-cleanup").addEventListener("click", async () => {
  if (!window.confirm("确定立即执行过期安全数据清理吗？")) return;
  try {
    const value = await api("/api/v1/admin/maintenance/cleanup", { method: "POST" });
    document.querySelector("#maintenance-output").textContent = JSON.stringify(value, null, 2);
    await Promise.all([loadKeys(), loadAudit()]);
    setStatus("过期安全数据清理完成。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.querySelector("#user-rows").addEventListener("click", (event) => {
  const target = event.target.closest("[data-action='edit-user']");
  if (!target) return;
  const user = state.users.find((item) => item.id === target.dataset.value);
  if (user) openUser(user);
});

document.querySelector("#client-rows").addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const client = state.clients.find((item) => item.id === target.dataset.value);
  if (!client) return;
  if (target.dataset.action === "edit-client") {
    openClient(client);
    return;
  }
  if (target.dataset.action === "show-integration") {
    try {
      showIntegration(await api(`/api/v1/admin/clients/${client.id}/integration`));
    } catch (error) {
      setStatus(error.message, "error");
    }
  }
});

clearConsole();
applyPermissions();
activateSection(location.hash.slice(1));
refreshAll();
