const accountState = {
  csrfToken: "",
  profile: null,
  sessions: [],
  mfa: null,
  recoveryCodes: [],
};

const accountStatus = document.querySelector("#account-status");

function accountElement(tag, attributes = {}, children = []) {
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
  for (const child of children) node.append(child);
  return node;
}

function setAccountStatus(message, kind = "") {
  accountStatus.textContent = message;
  accountStatus.className = `console-status ${kind}`.trim();
}

function accountDate(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN");
}

async function accountAPI(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (options.method && options.method !== "GET") {
    headers.set("X-CSRF-Token", accountState.csrfToken);
  }
  const response = await fetch(path, { ...options, headers });
  const raw = await response.text();
  let body = null;
  if (raw) {
    try {
      body = JSON.parse(raw);
    } catch {
      body = { detail: raw };
    }
  }
  if (response.status === 401) {
    window.location.assign("/login?continue=%2Faccount");
    throw new Error("登录会话已失效");
  }
  if (!response.ok) {
    throw new Error(body?.detail || body?.title || `请求失败（${response.status}）`);
  }
  return body;
}

async function loadAccount() {
  setAccountStatus("正在读取账户安全状态…");
  try {
    const profile = await accountAPI("/api/v1/account/profile");
    accountState.profile = profile;
    accountState.csrfToken = profile.csrf_token;
    renderProfile(profile);
    await Promise.all([loadSessions(), loadMFA()]);
    setAccountStatus("账户安全状态已更新。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  }
}

function renderProfile(profile) {
  const user = profile.user;
  document.querySelector("#profile-name").textContent = user.display_name;
  document.querySelector("#profile-meta").textContent = `${user.username} · ${user.email || "未设置邮箱"} · ID ${user.id}`;
  document.querySelector("#identity-avatar").textContent = [...user.display_name][0]?.toUpperCase() || "C";
  const badge = document.querySelector("#profile-status");
  badge.textContent = user.status === "active" ? "正常" : user.status === "locked" ? "锁定" : "停用";
  badge.className = `badge ${user.status}`;
}

async function loadSessions() {
  const value = await accountAPI("/api/v1/account/sessions");
  accountState.csrfToken = value.csrf_token || accountState.csrfToken;
  accountState.sessions = value.items || [];
  renderSessions();
}

function renderSessions() {
  const list = document.querySelector("#session-list");
  list.replaceChildren();
  if (!accountState.sessions.length) {
    list.append(accountElement("p", { className: "empty", text: "当前没有有效会话。" }));
    return;
  }
  for (const session of accountState.sessions) {
    const title = session.current ? "当前设备" : session.user_agent || "未知设备";
    const metadata = [
      session.ip_address || "未知 IP",
      `最近活动 ${accountDate(session.last_seen_at)}`,
      `到期 ${accountDate(session.expires_at)}`,
    ].join(" · ");
    const methods = (session.authentication_methods || []).join(" + ") || "未记录";
    const revoke = accountElement("button", {
      type: "button",
      className: session.current ? "danger" : "secondary",
      text: session.current ? "退出当前设备" : "撤销会话",
      dataset: { action: "revoke-session", sessionId: session.id, current: String(Boolean(session.current)) },
    });
    list.append(accountElement("article", { className: "session-item" }, [
      accountElement("div", { className: "session-icon", text: session.current ? "本机" : "设备" }),
      accountElement("div", { className: "session-details" }, [
        accountElement("div", {}, [
          accountElement("strong", { text: title }),
          accountElement("span", { className: "badge active", text: session.current ? "当前" : "有效" }),
        ]),
        accountElement("small", { text: metadata }),
        accountElement("small", { text: `认证方式 ${methods} · ${session.assurance_level || "AAL1"}` }),
      ]),
      revoke,
    ]));
  }
}

document.querySelector("#session-list").addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action='revoke-session']");
  if (!target) return;
  const current = target.dataset.current === "true";
  const prompt = current ? "退出当前设备后需要重新登录，确定继续吗？" : "确定撤销这个登录会话吗？";
  if (!window.confirm(prompt)) return;
  target.disabled = true;
  try {
    await accountAPI(`/api/v1/account/sessions/${target.dataset.sessionId}`, { method: "DELETE" });
    if (current) {
      window.location.assign("/login?continue=%2Faccount");
      return;
    }
    await loadSessions();
    setAccountStatus("登录会话已撤销。", "success");
  } catch (error) {
    target.disabled = false;
    setAccountStatus(error.message, "error");
  }
});

document.querySelector("#refresh-sessions").addEventListener("click", async () => {
  try {
    await loadSessions();
    setAccountStatus("登录会话已刷新。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  }
});

document.querySelector("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  if (data.get("new_password") !== data.get("confirm_password")) {
    setAccountStatus("两次输入的新密码不一致。", "error");
    return;
  }
  const submit = form.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    await accountAPI("/api/v1/account/password", {
      method: "PUT",
      body: JSON.stringify({
        current_password: data.get("current_password"),
        new_password: data.get("new_password"),
      }),
    });
    form.reset();
    await loadSessions();
    setAccountStatus("密码已更新，其他设备的会话已撤销。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

async function loadMFA() {
  const value = await accountAPI("/api/v1/account/mfa");
  accountState.csrfToken = value.csrf_token || accountState.csrfToken;
  accountState.mfa = value.status;
  renderMFA();
}

function renderMFA() {
  const status = accountState.mfa;
  const badge = document.querySelector("#mfa-badge");
  const summary = document.querySelector("#mfa-summary");
  const unavailable = document.querySelector("#mfa-unavailable");
  const setupForm = document.querySelector("#mfa-setup-form");
  const disableForm = document.querySelector("#mfa-disable-form");

  unavailable.classList.toggle("hidden", status.available);
  setupForm.classList.add("hidden");
  disableForm.classList.add("hidden");
  if (!status.available) {
    badge.textContent = "不可用";
    badge.className = "badge disabled";
    summary.textContent = "当前部署尚未启用 TOTP 多因素认证。";
    return;
  }
  if (status.enabled) {
    badge.textContent = "已启用";
    badge.className = "badge active";
    summary.textContent = `TOTP 已启用，剩余 ${status.recovery_codes} 枚恢复码${status.verified_at ? `，启用于 ${accountDate(status.verified_at)}` : ""}。`;
    disableForm.classList.remove("hidden");
    return;
  }
  badge.textContent = status.pending ? "待验证" : "未启用";
  badge.className = `badge ${status.pending ? "locked" : "disabled"}`;
  summary.textContent = status.pending ? "上次配置尚未验证，可以重新开始并生成新的密钥与恢复码。" : "启用认证器动态口令，为密码登录增加第二重保护。";
  setupForm.classList.remove("hidden");
}

document.querySelector("#mfa-setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const submit = form.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    const setup = await accountAPI("/api/v1/account/mfa/totp/setup", {
      method: "POST",
      body: JSON.stringify({ current_password: data.get("current_password") }),
    });
    form.reset();
    accountState.recoveryCodes = setup.recovery_codes || [];
    document.querySelector("#mfa-secret").textContent = setup.secret;
    document.querySelector("#mfa-uri").value = setup.otpauth_uri;
    const codes = document.querySelector("#recovery-codes");
    codes.replaceChildren(...accountState.recoveryCodes.map((code) => accountElement("code", { text: code })));
    document.querySelector("#mfa-setup-result").classList.remove("hidden");
    setAccountStatus("认证器配置已生成，请保存恢复码并输入动态口令完成启用。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

document.querySelector("#copy-recovery-codes").addEventListener("click", async (event) => {
  const copyButton = event.currentTarget;
  try {
    await navigator.clipboard.writeText(accountState.recoveryCodes.join("\n"));
    copyButton.textContent = "已复制";
    setTimeout(() => { copyButton.textContent = "复制恢复码"; }, 1500);
  } catch {
    setAccountStatus("浏览器未允许访问剪贴板，请手动复制恢复码。", "error");
  }
});

document.querySelector("#mfa-enable-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const submit = form.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    await accountAPI("/api/v1/account/mfa/totp/enable", {
      method: "POST",
      body: JSON.stringify({ code: data.get("code") }),
    });
    form.reset();
    accountState.recoveryCodes = [];
    document.querySelector("#recovery-codes").replaceChildren();
    document.querySelector("#mfa-secret").textContent = "";
    document.querySelector("#mfa-uri").value = "";
    document.querySelector("#mfa-setup-result").classList.add("hidden");
    await loadMFA();
    setAccountStatus("多因素认证已启用。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

document.querySelector("#mfa-disable-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!window.confirm("关闭 MFA 会降低账户安全性，确定继续吗？")) return;
  const form = event.currentTarget;
  const data = new FormData(form);
  const submit = form.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    await accountAPI("/api/v1/account/mfa/totp", {
      method: "DELETE",
      body: JSON.stringify({
        current_password: data.get("current_password"),
        code: data.get("code"),
      }),
    });
    form.reset();
    await loadMFA();
    setAccountStatus("多因素认证已关闭。", "success");
  } catch (error) {
    setAccountStatus(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

loadAccount();
