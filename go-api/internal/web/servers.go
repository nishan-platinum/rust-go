package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/provision"
	"github.com/example/rust-go/go-api/internal/store"
)

var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)

type serversData struct {
	Servers []store.DBServer
	Types   []string
	Ports   map[string]int
	Form    store.DBServer
	Errors  []string
}

func (wb *Web) serversPage(w http.ResponseWriter, r *http.Request) {
	wb.renderServers(w, r, http.StatusOK, serversData{Form: store.DBServer{DBType: "postgres", Port: 5432}})
}

func (wb *Web) renderServers(w http.ResponseWriter, r *http.Request, code int, d serversData) {
	servers, err := wb.Store.ListServers(r.Context())
	if err != nil {
		slog.Error("list servers", "err", err)
		d.Errors = append(d.Errors, "Could not load servers.")
	}
	d.Servers, d.Types, d.Ports = servers, provision.DBTypes, provision.DefaultPorts
	wb.render(w, r, code, "servers", "Database servers", d)
}

func (wb *Web) createServer(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	d := store.DBServer{
		Name:          strings.ToLower(strings.TrimSpace(r.PostFormValue("name"))),
		DBType:        r.PostFormValue("db_type"),
		Host:          strings.TrimSpace(r.PostFormValue("host")),
		Port:          port,
		AdminUsername: strings.TrimSpace(r.PostFormValue("admin_username")),
		AdminPassword: r.PostFormValue("admin_password"),
		Params:        parseParams(r.PostFormValue("params")),
	}
	var errs []string
	if !serverNameRe.MatchString(d.Name) {
		errs = append(errs, "Name must be 2-41 chars of a-z, 0-9 and '-'.")
	}
	if _, ok := provision.DefaultPorts[d.DBType]; !ok {
		errs = append(errs, "Choose a database type.")
	}
	if d.Host == "" || port < 1 || port > 65535 || d.AdminUsername == "" || d.AdminPassword == "" {
		errs = append(errs, "Host, port, admin username and admin password are required.")
	}
	if len(errs) == 0 {
		if err := wb.Provision.CheckConnection(r.Context(), engine.ServerProbe(d)); err != nil {
			errs = append(errs, "Connection check failed: "+err.Error())
		}
	}
	if len(errs) == 0 {
		if _, err := wb.Store.CreateServer(r.Context(), d); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				errs = append(errs, "A server with this name already exists.")
			} else {
				slog.Error("create server", "err", err)
				errs = append(errs, "Could not save server.")
			}
		}
	}
	if len(errs) > 0 {
		d.AdminPassword = ""
		wb.renderServers(w, r, http.StatusUnprocessableEntity, serversData{Form: d, Errors: errs})
		return
	}
	wb.Store.Audit(r.Context(), actor(r), "server_added", "", fmt.Sprintf("%s %s %s:%d", d.Name, d.DBType, d.Host, d.Port))
	setFlash(w, "ok", "Server "+d.Name+" added.")
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (wb *Web) serverFromPath(r *http.Request) (store.DBServer, error) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return wb.Store.GetServer(r.Context(), id)
}

func (wb *Web) testServer(w http.ResponseWriter, r *http.Request) {
	d, err := wb.serverFromPath(r)
	if err != nil {
		wb.result(w, actionResult{Title: "Unknown server"})
		return
	}
	if err := wb.Provision.CheckConnection(r.Context(), engine.ServerProbe(d)); err != nil {
		wb.result(w, actionResult{Title: "Connection failed", Detail: err.Error()})
		return
	}
	wb.result(w, actionResult{OK: true, Title: "Connected", Detail: "Admin login works on " + d.Host + "."})
}

func (wb *Web) defaultServer(w http.ResponseWriter, r *http.Request) {
	d, err := wb.serverFromPath(r)
	if err == nil {
		err = wb.Store.SetDefaultServer(r.Context(), d.ID)
	}
	if err != nil {
		setFlash(w, "err", "Could not set default: "+err.Error())
	} else {
		wb.Store.Audit(r.Context(), actor(r), "server_default", "", d.Name)
		setFlash(w, "ok", d.Name+" is now the default "+d.DBType+" server for new tenants.")
	}
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (wb *Web) deleteServer(w http.ResponseWriter, r *http.Request) {
	d, err := wb.serverFromPath(r)
	if err == nil {
		err = wb.Store.DeleteServer(r.Context(), d.ID)
	}
	switch {
	case errors.Is(err, store.ErrInUse):
		setFlash(w, "err", "Server "+d.Name+" still hosts tenants; delete or move them first.")
	case err != nil:
		setFlash(w, "err", "Delete failed: "+err.Error())
	default:
		wb.Store.Audit(r.Context(), actor(r), "server_removed", "", d.Name)
		setFlash(w, "ok", "Server "+d.Name+" removed. Databases on it were not touched.")
	}
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}
