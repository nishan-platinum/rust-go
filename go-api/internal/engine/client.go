// Package engine is the gRPC client for the Rust DB engine.
package engine

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/store"
)

type Client struct {
	pb.DbEngineClient
	conn    *grpc.ClientConn
	timeout time.Duration
}

// tokenCreds attaches the shared internal token to every call.
type tokenCreds string

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(t)}, nil
}
func (tokenCreds) RequireTransportSecurity() bool { return false }

func Dial(addr, token string, timeout time.Duration) (*Client, error) {
	c := &Client{timeout: timeout}
	conn, err := grpc.NewClient(addr,
		// TODO(prod): switch to mTLS credentials and set RequireTransportSecurity.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(tokenCreds(token)),
		grpc.WithUnaryInterceptor(c.deadline),
	)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.DbEngineClient = pb.NewDbEngineClient(conn)
	return c, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// deadline gives every call a deadline unless the caller already set one.
func (c *Client) deadline(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

var dbTypes = map[string]pb.DbType{
	"postgres": pb.DbType_DB_TYPE_POSTGRES,
	"mysql":    pb.DbType_DB_TYPE_MYSQL,
	"mariadb":  pb.DbType_DB_TYPE_MARIADB,
	"mongodb":  pb.DbType_DB_TYPE_MONGODB,
}

func DBTypeName(t pb.DbType) string {
	for k, v := range dbTypes {
		if v == t {
			return k
		}
	}
	return "unknown"
}

// Conn converts a registry tenant into the wire form sent with every call.
func Conn(t store.Tenant) *pb.TenantConn {
	return &pb.TenantConn{
		TenantId:      t.ID,
		ConfigVersion: t.ConfigVersion,
		DbType:        dbTypes[t.DBType],
		Host:          t.Host,
		Port:          uint32(t.Port),
		Username:      t.Username,
		Password:      t.Password,
		Database:      t.Database,
		Params:        t.Params,
	}
}

func Req(t store.Tenant) *pb.TenantRequest { return &pb.TenantRequest{Conn: Conn(t)} }

// Server converts a database server (admin credentials) to its wire form.
func Server(d store.DBServer) *pb.ServerConn {
	return &pb.ServerConn{
		DbType:        dbTypes[d.DBType],
		Host:          d.Host,
		Port:          uint32(d.Port),
		AdminUsername: d.AdminUsername,
		AdminPassword: d.AdminPassword,
		Params:        d.Params,
	}
}

// ServerProbe builds a throwaway TenantConn that logs in to the server's
// maintenance database with the admin credentials, for TestConnection.
func ServerProbe(d store.DBServer) *pb.TenantConn {
	db := map[string]string{"postgres": "postgres", "mysql": "mysql", "mariadb": "mysql", "mongodb": "admin"}[d.DBType]
	if v := d.Params["maintenance_db"]; v != "" {
		db = v
	}
	params := map[string]string{}
	for k, v := range d.Params {
		params[k] = v
	}
	if d.DBType == "mongodb" && params["authSource"] == "" {
		params["authSource"] = "admin"
	}
	return &pb.TenantConn{
		TenantId: "server-probe", ConfigVersion: 1, DbType: dbTypes[d.DBType],
		Host: d.Host, Port: uint32(d.Port), Username: d.AdminUsername, Password: d.AdminPassword,
		Database: db, Params: params,
	}
}
