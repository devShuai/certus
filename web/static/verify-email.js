const verifyStatus = document.querySelector("#verify-status");
const verifyTitle = document.querySelector("#verify-title");
const verifySummary = document.querySelector("#verify-summary");
const verifyCSRF = document.querySelector("#verify-csrf");

function setVerifyStatus(message, kind = "") {
  verifyStatus.textContent = message;
  verifyStatus.className = `console-status ${kind}`.trim();
}

function verifyRedirect(to) {
  window.setTimeout(() => {
    window.location.assign(to);
  }, 1500);
}

async function submitVerification(token) {
  const response = await fetch("/api/v1/account/email/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": verifyCSRF.value,
    },
    body: JSON.stringify({ token }),
  });
  if (response.status === 401) {
    window.location.assign(`/login?continue=${encodeURIComponent(`/account/verify-email?token=${encodeURIComponent(token)}`)}`);
    throw new Error("需要先登录");
  }
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
    throw new Error(body?.detail || `验证失败（${response.status}）`);
  }
  return body;
}

async function runVerification() {
  const token = new URLSearchParams(window.location.search).get("token");
  if (!token) {
    verifyTitle.textContent = "缺少验证凭据";
    verifySummary.textContent = "邮件中的验证链接不完整，请返回账户安全中心重新发送验证邮件。";
    setVerifyStatus("验证链接无效。", "error");
    return;
  }
  try {
    await submitVerification(token);
    verifyTitle.textContent = "邮箱验证成功";
    verifySummary.textContent = "你的邮箱所有权已验证，即将返回账户安全中心。";
    setVerifyStatus("验证完成。", "success");
    verifyRedirect("/account?verified=1");
  } catch (error) {
    verifyTitle.textContent = "邮箱验证失败";
    verifySummary.textContent = error.message;
    setVerifyStatus("验证未完成。", "error");
    verifyRedirect("/account");
  }
}

runVerification();
