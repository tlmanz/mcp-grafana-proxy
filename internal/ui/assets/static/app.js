"use strict";

// All server data goes into the page with textContent, never innerHTML.

const csrf = document.querySelector('meta[name="csrf-token"]').content;
const $ = (sel, root = document) => root.querySelector(sel);

let editing = null; // name of the environment being edited, or null when adding

async function api(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (resp.status === 204) return null;
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function flash(message, ok) {
  const el = $("#flash");
  el.textContent = message;
  el.className = ok ? "ok" : "fail";
  el.hidden = false;
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = label; }, 1500);
  } catch {
    window.prompt("Copy this:", text);
  }
}

function mcpConfig(env) {
  const vars = { GRAFANA_URL: env.grafana_url };
  if (!env.has_grafana_token) vars.GRAFANA_SERVICE_ACCOUNT_TOKEN = "glsa_...";
  const config = { mcpServers: { [`grafana-${env.name}`]: { command: "mcp-grafana", env: vars } } };
  return JSON.stringify(config, null, 2);
}

function showResults(list, results) {
  list.replaceChildren(...results.map((r) => {
    const li = document.createElement("li");
    li.className = r.level;
    li.textContent = r.message;
    return li;
  }));
  list.hidden = false;
}

function renderCard(env) {
  const card = $("#env-card").content.firstElementChild.cloneNode(true);
  $(".env-name", card).textContent = env.name;
  $(".env-upstream", card).textContent = env.upstream;
  $(".env-client", card).textContent = env.client_id;
  $(".env-grafana-url", card).textContent = env.grafana_url;
  $(".env-token", card).textContent = env.has_grafana_token ? "Saved" : "Not set (mcp-grafana must send one)";

  const badge = $(".badge", card);
  const signedIn = Boolean(env.signed_in_at);
  if (signedIn) {
    badge.textContent = `Signed in as ${env.signed_in_as || "unknown"}`;
    badge.classList.add("ok");
    badge.title = `Since ${new Date(env.signed_in_at).toLocaleString()}`;
  } else {
    badge.textContent = "Not signed in";
  }

  const signIn = $(".sign-in", card);
  signIn.textContent = signedIn ? "Sign in again" : "Sign in";
  signIn.addEventListener("click", () => {
    const q = new URLSearchParams({ env: env.name, csrf });
    window.location.assign(`/oauth/start?${q}`);
  });

  const results = $(".results", card);
  const test = $(".test", card);
  test.addEventListener("click", async () => {
    test.disabled = true;
    test.textContent = "Testing...";
    try {
      const data = await api("POST", `/api/environments/${env.name}/test`);
      showResults(results, data.results);
    } catch (err) {
      showResults(results, [{ level: "fail", message: err.message }]);
    } finally {
      test.disabled = false;
      test.textContent = "Test";
    }
  });

  $(".copy-url", card).addEventListener("click", (e) => copy(env.grafana_url, e.currentTarget));
  $(".copy-config", card).addEventListener("click", (e) => copy(mcpConfig(env), e.currentTarget));
  $(".edit", card).addEventListener("click", () => openForm(env));

  const signOut = $(".sign-out", card);
  signOut.hidden = !signedIn;
  signOut.addEventListener("click", async () => {
    try {
      await api("POST", `/api/environments/${env.name}/signout`);
      flash(`Signed out of ${env.name}.`, true);
      load();
    } catch (err) {
      flash(err.message, false);
    }
  });

  $(".delete", card).addEventListener("click", async () => {
    if (!window.confirm(`Delete environment "${env.name}" and its saved secrets?`)) return;
    try {
      await api("DELETE", `/api/environments/${env.name}`);
      flash(`Deleted ${env.name}.`, true);
      load();
    } catch (err) {
      flash(err.message, false);
    }
  });
  return card;
}

async function load() {
  try {
    const data = await api("GET", "/api/environments");
    $("#envs").replaceChildren(...data.environments.map(renderCard));
    $("#empty").hidden = data.environments.length > 0;
  } catch (err) {
    flash(`Could not load environments: ${err.message}`, false);
  }
}

// Fields are read through elements.namedItem: on a form, properties such as
// form.name refer to the form itself, not to the input with that name.
const field = (form, name) => form.elements.namedItem(name);

function openForm(env) {
  const form = $("#env-form");
  const f = (name) => field(form, name);
  form.reset();
  editing = env ? env.name : null;
  $("#form-title").textContent = env ? `Edit ${env.name}` : "Add environment";
  $("#form-error").hidden = true;
  f("name").disabled = Boolean(env);
  f("client_secret").required = !env;
  f("client_secret").placeholder = env ? "Saved. Leave empty to keep it" : "";
  f("grafana_token").placeholder = env && env.has_grafana_token ? "Saved. Leave empty to keep it" : "glsa_...";
  $("#clear-token-row").hidden = !(env && env.has_grafana_token);
  if (env) {
    f("name").value = env.name;
    f("upstream").value = env.upstream;
    f("client_id").value = env.client_id;
    f("account").value = env.account || "";
  }
  form.hidden = false;
  f(env ? "upstream" : "name").focus();
}

function closeForm() {
  const form = $("#env-form");
  form.reset();
  form.hidden = true;
  editing = null;
}

async function submitForm(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const f = (name) => field(form, name);
  const name = editing || f("name").value.trim();
  const body = {
    upstream: f("upstream").value.trim(),
    client_id: f("client_id").value.trim(),
    client_secret: f("client_secret").value,
    account: f("account").value.trim(),
    grafana_token: f("grafana_token").value,
    clear_grafana_token: f("clear_grafana_token").checked,
  };
  try {
    await api("PUT", `/api/environments/${encodeURIComponent(name)}`, body);
    flash(`Saved ${name}.${editing ? "" : " Now sign in to it."}`, true);
    closeForm();
    load();
  } catch (err) {
    const el = $("#form-error");
    el.textContent = err.message;
    el.hidden = false;
  }
}

function showRedirectMessage() {
  const q = new URLSearchParams(window.location.search);
  if (q.has("signed_in")) flash(`Signed in to ${q.get("signed_in")}.`, true);
  if (q.has("error")) flash(`Sign-in failed: ${q.get("error")}`, false);
  if (q.has("signed_in") || q.has("error")) history.replaceState(null, "", "/");
}

document.addEventListener("DOMContentLoaded", () => {
  $("#add").addEventListener("click", () => openForm(null));
  $("#cancel").addEventListener("click", closeForm);
  $("#env-form").addEventListener("submit", submitForm);
  document.querySelectorAll("[data-copy]").forEach((b) => {
    b.addEventListener("click", () => copy(b.dataset.copy, b));
  });
  showRedirectMessage();
  load();
});
