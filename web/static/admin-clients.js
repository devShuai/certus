const form = document.querySelector("#client-form");
const tokenInput = document.querySelector("#admin-token");
const statusElement = document.querySelector("#form-status");
const resultCard = document.querySelector("#integration-card");
const output = document.querySelector("#integration-output");
const secretWarning = document.querySelector("#secret-warning");
const copyButton = document.querySelector("#copy-integration");

tokenInput.value = sessionStorage.getItem("certus.adminToken") || "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusElement.textContent = "正在保存…";
  resultCard.classList.add("hidden");

  const data = new FormData(form);
  const token = data.get("admin_token");
  const payload = {
    id: data.get("id"),
    name: data.get("name"),
    description: data.get("description"),
    application_type: data.get("application_type"),
    protocols: data.getAll("protocols"),
    grant_types: data.getAll("grant_types"),
    redirect_uris: data.get("redirect_uris").split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
    login_methods: data.getAll("login_methods"),
    allowed_scopes: data.get("allowed_scopes").split(/\s+/).filter(Boolean),
    cas_version: data.get("cas_version"),
    cas_service_urls: data.get("cas_service_urls").split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
    cas_proxy: data.has("cas_proxy"),
    cas_gateway: data.has("cas_gateway"),
    cas_renew: data.has("cas_renew"),
    cas_single_logout: data.has("cas_single_logout"),
  };

  try {
    const response = await fetch("/api/v1/admin/clients", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.detail || "保存失败");
    }
    sessionStorage.setItem("certus.adminToken", token);
    output.textContent = JSON.stringify(body.integration, null, 2);
    secretWarning.classList.toggle("hidden", !body.integration.client_secret);
    resultCard.classList.remove("hidden");
    statusElement.textContent = "已保存";
    resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    statusElement.textContent = error.message;
  }
});

copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(output.textContent);
  copyButton.textContent = "已复制";
  setTimeout(() => { copyButton.textContent = "复制参数"; }, 1500);
});
