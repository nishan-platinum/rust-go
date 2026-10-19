// Attach the CSRF token to every HTMX request.
document.addEventListener("htmx:configRequest", (e) => {
  const m = document.querySelector('meta[name="csrf-token"]');
  if (m) e.detail.headers["X-CSRF-Token"] = m.content;
});

const DEFAULT_PORTS = { postgres: "5432", mysql: "3306", mariadb: "3306", mongodb: "27017" };

// Set a default port when the DB type changes, unless the user typed a custom one.
function syncPort(type) {
  const port = document.getElementById("port");
  if (!port || !DEFAULT_PORTS[type]) return;
  if (!port.value || Object.values(DEFAULT_PORTS).includes(port.value)) port.value = DEFAULT_PORTS[type];
}

// New-tenant wizard: show only servers of the chosen type, and the section for the chosen mode.
function syncWizard() {
  const form = document.getElementById("tenant-form");
  if (!form) return;
  const type = (form.querySelector('input[name="db_type"]:checked') || {}).value;
  const mode = (form.querySelector('input[name="mode"]:checked') || {}).value;
  if (mode) form.dataset.mode = mode;
  const address = (form.querySelector('input[name="address"]:checked') || {}).value;
  if (address) form.dataset.address = address;
  const id = document.getElementById("t-id");
  for (const el of form.querySelectorAll(".id-preview")) el.textContent = (id && id.value) || "acme";
  const sel = document.getElementById("server_id");
  if (sel) {
    for (const o of sel.options) {
      if (!o.dataset.type) continue;
      o.hidden = o.disabled = o.dataset.type !== type;
      if (o.disabled && o.selected) sel.value = "0";
    }
  }
}

// Subdomain follows the tenant name until the user edits it directly.
function slugify(s) {
  return s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 28).replace(/-+$/, "");
}

document.addEventListener("input", (e) => {
  if (e.target.id === "t-id") {
    e.target.dataset.touched = "1";
    syncWizard();
  }
  if (e.target.id === "t-name") {
    const id = document.getElementById("t-id");
    if (id && !id.dataset.touched) {
      id.value = slugify(e.target.value);
      id.dispatchEvent(new Event("input", { bubbles: true }));
      delete id.dataset.touched;
    }
  }
});

document.addEventListener("change", (e) => {
  if (e.target.id === "db_type") syncPort(e.target.value);
  if (e.target.name === "db_type" && e.target.type === "radio") syncPort(e.target.value);
  if (["db_type", "mode", "address"].includes(e.target.name)) syncWizard();
});

document.addEventListener("DOMContentLoaded", syncWizard);

// Confirmation for plain (non-HTMX) destructive forms.
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset && e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// Select a minted token on click for easy copying.
document.addEventListener("click", (e) => {
  if (e.target.classList && e.target.classList.contains("token")) e.target.select();
});
