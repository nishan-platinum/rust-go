package web

import (
	"net/http"
	"strings"

	"github.com/example/rust-go/go-api/internal/store"
)

type domainsData struct {
	Tenant  store.Tenant
	Domains []store.Domain
	DevAuto bool
	Input   string
	Error   string
}

func (wb *Web) domainsPage(w http.ResponseWriter, r *http.Request) {
	wb.renderDomains(w, r, http.StatusOK, "", "")
}

func (wb *Web) renderDomains(w http.ResponseWriter, r *http.Request, code int, input, errMsg string) {
	t, ok := wb.Registry.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	list, err := wb.Store.ListDomains(r.Context(), t.ID)
	if err != nil {
		errMsg = "Could not load domains."
	}
	t.Password = ""
	wb.render(w, r, code, "tenant_domains", "Tenants", domainsData{
		Tenant: t, Domains: list,
		DevAuto: wb.Domains.DevAutoVerify, Input: input, Error: errMsg,
	})
}

func (wb *Web) addDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	raw := r.PostFormValue("domain")
	d, err := wb.Domains.Add(r.Context(), id, raw, actor(r))
	switch {
	case d.Domain == "": // rejected; show the form again
		wb.renderDomains(w, r, http.StatusUnprocessableEntity, raw, err.Error())
		return
	case err != nil:
		setFlash(w, "err", err.Error())
	case d.Verified():
		setFlash(w, "ok", d.Domain+" added and live.")
	default:
		setFlash(w, "ok", d.Domain+" added. Ask the client to create the DNS records below, then click Verify.")
	}
	http.Redirect(w, r, "/tenants/"+id+"/domains", http.StatusSeeOther)
}

// domainAction runs verify / primary / delete and goes back to the list.
func (wb *Web) domainAction(w http.ResponseWriter, r *http.Request) {
	id, d := r.PathValue("id"), strings.ToLower(r.PathValue("domain"))
	var err error
	var ok string
	switch r.PathValue("action") {
	case "verify":
		err, ok = wb.Domains.Verify(r.Context(), id, d, actor(r)), d+" verified. It now opens this workspace."
	case "primary":
		err, ok = wb.Domains.SetPrimary(r.Context(), id, d, actor(r)), d+" is now the primary domain."
	case "delete":
		err, ok = wb.Domains.Remove(r.Context(), id, d, actor(r)), d+" removed. It stopped working immediately."
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		setFlash(w, "err", err.Error())
	} else {
		setFlash(w, "ok", ok)
	}
	http.Redirect(w, r, "/tenants/"+id+"/domains", http.StatusSeeOther)
}

// toggleSubdomain switches <id>.<base> on or off for a tenant.
func (wb *Web) toggleSubdomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	on := r.PostFormValue("on") == "true"
	if err := wb.Domains.SetSubdomain(r.Context(), id, on, actor(r)); err != nil {
		setFlash(w, "err", err.Error())
	} else if on {
		setFlash(w, "ok", "Subdomain "+id+"."+wb.BaseDomain+" is on.")
	} else {
		setFlash(w, "ok", "Subdomain "+id+"."+wb.BaseDomain+" is off; the workspace is only reachable on its own domain.")
	}
	http.Redirect(w, r, "/tenants/"+id+"/domains", http.StatusSeeOther)
}
