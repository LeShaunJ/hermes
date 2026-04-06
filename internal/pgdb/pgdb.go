// Package pgdb implements a minimal PostgreSQL wire-protocol (v3) client.
// It covers exactly the operations hermes needs: connect, exec, query, scan.
// No external dependencies — only the Go standard library.
package pgdb

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── message type bytes (backend → frontend) ──────────────────────────────────

const (
	beAuth            = 'R'
	beBackendKeyData  = 'K'
	beCommandComplete = 'C'
	beDataRow         = 'D'
	beErrorResponse   = 'E'
	beNoticeResponse  = 'N'
	beParameterStatus = 'S'
	beReadyForQuery   = 'Z'
	beRowDescription  = 'T'
	beEmptyQuery      = 'I'
	beNoData          = 'n'
	beParseComplete   = '1'
	beBindComplete    = '2'
)

// auth sub-types
const (
	authOK  = 0
	authMD5 = 5
)

// ── pool ─────────────────────────────────────────────────────────────────────

// Pool is a fixed-size connection pool for a single PostgreSQL server.
type Pool struct {
	mu   sync.Mutex
	idle []*Conn
	cfg  Config
	size int
}

// Config holds the parameters needed to open a PostgreSQL connection.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string // "disable" is the only mode we handle; anything else is ignored
}

// ParseDSN parses a libpq-style DSN string:
//
//	host=... port=... user=... password=... dbname=... sslmode=...
func ParseDSN(dsn string) (Config, error) {
	cfg := Config{Host: "localhost", Port: 5432, SSLMode: "disable"}
	for _, kv := range strings.Fields(dsn) {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		v := strings.Trim(parts[1], "'")
		switch parts[0] {
		case "host":
			cfg.Host = v
		case "port":
			n, err := strconv.Atoi(v)
			if err != nil {
				return Config{}, fmt.Errorf("invalid port %q", v)
			}
			cfg.Port = n
		case "user":
			cfg.User = v
		case "password":
			cfg.Password = v
		case "dbname":
			cfg.Database = v
		case "sslmode":
			cfg.SSLMode = v
		}
	}
	return cfg, nil
}

// NewPool creates a pool with at most size connections.
func NewPool(cfg Config, size int) *Pool {
	if size <= 0 {
		size = 5
	}
	return &Pool{cfg: cfg, size: size}
}

// Acquire returns an idle connection or opens a new one.
func (p *Pool) Acquire() (*PoolConn, error) {
	p.mu.Lock()
	if len(p.idle) > 0 {
		c := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.mu.Unlock()
		return &PoolConn{Conn: c, pool: p}, nil
	}
	p.mu.Unlock()

	c, err := connect(p.cfg)
	if err != nil {
		return nil, err
	}
	return &PoolConn{Conn: c, pool: p}, nil
}

// release returns c to the pool (or closes it if the pool is full).
func (p *Pool) release(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) >= p.size {
		c.Close()
		return
	}
	p.idle = append(p.idle, c)
}

// Close closes all idle connections.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.idle {
		c.Close()
	}
	p.idle = nil
}

// Exec runs a statement that returns no rows.
func (p *Pool) Exec(sql string) error {
	pc, err := p.Acquire()
	if err != nil {
		return err
	}
	defer pc.Release()
	return pc.Exec(sql)
}

// Query runs a query and returns a Rows scanner.
// The caller MUST call Rows.Close() when done.
func (p *Pool) Query(sql string) (*Rows, error) {
	pc, err := p.Acquire()
	if err != nil {
		return nil, err
	}
	rows, err := pc.query(sql)
	if err != nil {
		pc.Release()
		return nil, err
	}
	rows.pc = pc
	return rows, nil
}

// QueryRow runs a query expected to return at most one row.
func (p *Pool) QueryRow(sql string) *Row {
	rows, err := p.Query(sql)
	return &Row{rows: rows, err: err}
}

// PoolConn wraps a Conn with pool-return semantics.
type PoolConn struct {
	*Conn
	pool     *Pool
	released bool
}

func (pc *PoolConn) Release() {
	if pc.released {
		return
	}
	pc.released = true
	if pc.Conn.broken {
		pc.Conn.Close()
		return
	}
	pc.pool.release(pc.Conn)
}

// ── connection ────────────────────────────────────────────────────────────────

// Conn is a single PostgreSQL connection.
type Conn struct {
	nc     net.Conn
	broken bool
}

func connect(cfg Config) (*Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	nc, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("pgdb: connect %s: %w", addr, err)
	}
	c := &Conn{nc: nc}

	// Send startup message.
	if err := c.sendStartup(cfg.User, cfg.Database); err != nil {
		nc.Close()
		return nil, err
	}

	// Authentication loop.
	for {
		msgType, payload, err := c.readMessage()
		if err != nil {
			nc.Close()
			return nil, err
		}
		switch msgType {
		case beAuth:
			if len(payload) < 4 {
				nc.Close()
				return nil, fmt.Errorf("pgdb: short auth message")
			}
			authType := int32(binary.BigEndian.Uint32(payload[:4]))
			switch authType {
			case authOK:
				// authenticated; now drain startup messages
				if err := c.drainStartup(); err != nil {
					nc.Close()
					return nil, err
				}
				return c, nil
			case authMD5:
				if len(payload) < 8 {
					nc.Close()
					return nil, fmt.Errorf("pgdb: short MD5 challenge")
				}
				salt := payload[4:8]
				pw := md5Password(cfg.User, cfg.Password, salt)
				if err := c.sendPassword(pw); err != nil {
					nc.Close()
					return nil, err
				}
			default:
				nc.Close()
				return nil, fmt.Errorf("pgdb: unsupported auth type %d", authType)
			}
		case beErrorResponse:
			nc.Close()
			return nil, parseError(payload)
		default:
			// ignore unexpected messages during auth
		}
	}
}

// drainStartup reads ParameterStatus / BackendKeyData until ReadyForQuery.
func (c *Conn) drainStartup() error {
	for {
		t, _, err := c.readMessage()
		if err != nil {
			return err
		}
		switch t {
		case beReadyForQuery:
			return nil
		case beErrorResponse:
			// shouldn't happen, but handle it
		}
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	// Send Terminate.
	_ = c.nc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.nc.Write([]byte{'X', 0, 0, 0, 4})
	return c.nc.Close()
}

// Exec runs a statement that returns no rows.
func (c *Conn) Exec(sql string) error {
	rows, err := c.query(sql)
	if err != nil {
		return err
	}
	return rows.Close()
}

// query sends a simple Query and returns Rows.
func (c *Conn) query(sql string) (*Rows, error) {
	if err := c.sendQuery(sql); err != nil {
		c.broken = true
		return nil, err
	}
	rows := &Rows{conn: c}
	// Read until RowDescription, CommandComplete(no rows), or error.
	for {
		t, payload, err := c.readMessage()
		if err != nil {
			c.broken = true
			return nil, err
		}
		switch t {
		case beRowDescription:
			rows.columns = parseRowDesc(payload)
			return rows, nil
		case beCommandComplete:
			rows.done = true
			// drain ReadyForQuery
			if err := rows.drainToReady(); err != nil {
				return nil, err
			}
			return rows, nil
		case beEmptyQuery:
			rows.done = true
			if err := rows.drainToReady(); err != nil {
				return nil, err
			}
			return rows, nil
		case beErrorResponse:
			rows.done = true
			pgErr := parseError(payload)
			// drain ReadyForQuery
			_ = rows.drainToReady()
			return nil, pgErr
		case beNoticeResponse:
			// ignore
		default:
			// unexpected; ignore
		}
	}
}

// ── row scanning ─────────────────────────────────────────────────────────────

// Rows is an iterator over query results.
type Rows struct {
	conn    *Conn
	pc      *PoolConn // non-nil when pool-owned
	columns []string
	current [][]byte
	done    bool
	err     error
}

// Columns returns the column names.
func (r *Rows) Columns() []string { return r.columns }

// Next advances to the next row. Returns false when done.
func (r *Rows) Next() bool {
	if r.done || r.err != nil {
		return false
	}
	for {
		t, payload, err := r.conn.readMessage()
		if err != nil {
			r.err = err
			r.conn.broken = true
			return false
		}
		switch t {
		case beDataRow:
			r.current = parseDataRow(payload)
			return true
		case beCommandComplete:
			r.done = true
			_ = r.drainToReady()
			return false
		case beErrorResponse:
			r.err = parseError(payload)
			_ = r.drainToReady()
			return false
		case beNoticeResponse:
			// ignore
		default:
			// ignore
		}
	}
}

// Scan copies the current row's columns into dest.
// Supported dest types: *string, *[]byte, *int64, *int, *bool,
// *time.Time (RFC3339 / postgres timestamp), *json.RawMessage.
// Use *interface{} or **string for nullable columns.
func (r *Rows) Scan(dest ...interface{}) error {
	if r.current == nil {
		return fmt.Errorf("pgdb: Scan called without a current row")
	}
	if len(dest) > len(r.current) {
		return fmt.Errorf("pgdb: Scan: too many destinations (%d) for %d columns", len(dest), len(r.current))
	}
	for i, d := range dest {
		col := r.current[i]
		if err := scanValue(col, d); err != nil {
			return fmt.Errorf("pgdb: Scan col %d: %w", i, err)
		}
	}
	return nil
}

// Err returns any error that occurred during iteration.
func (r *Rows) Err() error { return r.err }

// Close drains any remaining rows and returns the connection to the pool.
func (r *Rows) Close() error {
	if !r.done {
		for r.Next() {
		}
	}
	if r.pc != nil {
		r.pc.Release()
	}
	return r.err
}

// drainToReady reads until ReadyForQuery.
func (r *Rows) drainToReady() error {
	for {
		t, _, err := r.conn.readMessage()
		if err != nil {
			r.conn.broken = true
			return err
		}
		if t == beReadyForQuery {
			return nil
		}
	}
}

// Row is a single-row result (like sql.Row).
type Row struct {
	rows *Rows
	err  error
}

// Scan scans the single row into dest. Returns ErrNoRows if no rows.
func (r *Row) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	defer r.rows.Close()
	if !r.rows.Next() {
		if r.rows.Err() != nil {
			return r.rows.Err()
		}
		return ErrNoRows
	}
	return r.rows.Scan(dest...)
}

// ErrNoRows is returned when QueryRow finds no rows.
var ErrNoRows = fmt.Errorf("pgdb: no rows")

// ── wire helpers ──────────────────────────────────────────────────────────────

func (c *Conn) sendStartup(user, database string) error {
	var buf []byte
	buf = appendInt32(buf, 196608) // protocol 3.0
	buf = appendString(buf, "user")
	buf = appendString(buf, user)
	buf = appendString(buf, "database")
	buf = appendString(buf, database)
	buf = append(buf, 0) // terminator

	msg := make([]byte, 4+len(buf))
	binary.BigEndian.PutUint32(msg[:4], uint32(len(msg)))
	copy(msg[4:], buf)

	_ = c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.nc.Write(msg)
	return err
}

func (c *Conn) sendPassword(pw string) error {
	body := pw + "\x00"
	msg := make([]byte, 1+4+len(body))
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	copy(msg[5:], body)
	_ = c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.nc.Write(msg)
	return err
}

func (c *Conn) sendQuery(sql string) error {
	body := sql + "\x00"
	msg := make([]byte, 1+4+len(body))
	msg[0] = 'Q'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(body)))
	copy(msg[5:], body)
	_ = c.nc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := c.nc.Write(msg)
	return err
}

func (c *Conn) readMessage() (byte, []byte, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.nc, hdr); err != nil {
		return 0, nil, fmt.Errorf("pgdb: read header: %w", err)
	}
	msgType := hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
	if msgLen < 0 {
		return 0, nil, fmt.Errorf("pgdb: negative message length")
	}
	payload := make([]byte, msgLen)
	if msgLen > 0 {
		if _, err := io.ReadFull(c.nc, payload); err != nil {
			return 0, nil, fmt.Errorf("pgdb: read payload: %w", err)
		}
	}
	return msgType, payload, nil
}

// ── parsing helpers ───────────────────────────────────────────────────────────

func parseRowDesc(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	cols := make([]string, 0, n)
	pos := 2
	for i := 0; i < n; i++ {
		end := strings.IndexByte(string(payload[pos:]), 0)
		if end < 0 {
			break
		}
		cols = append(cols, string(payload[pos:pos+end]))
		pos += end + 1 + 18 // name\0 + tableOID(4)+attrNum(2)+typeOID(4)+typeSize(2)+typeMod(4)+format(2)
	}
	return cols
}

func parseDataRow(payload []byte) [][]byte {
	if len(payload) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	cols := make([][]byte, n)
	pos := 2
	for i := 0; i < n; i++ {
		if pos+4 > len(payload) {
			break
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[pos : pos+4])))
		pos += 4
		if colLen < 0 {
			// NULL
			cols[i] = nil
			continue
		}
		cols[i] = payload[pos : pos+colLen]
		pos += colLen
	}
	return cols
}

func parseError(payload []byte) error {
	fields := map[byte]string{}
	for i := 0; i < len(payload); {
		code := payload[i]
		i++
		if code == 0 {
			break
		}
		end := strings.IndexByte(string(payload[i:]), 0)
		if end < 0 {
			break
		}
		fields[code] = string(payload[i : i+end])
		i += end + 1
	}
	sev := fields['S']
	msg := fields['M']
	detail := fields['D']
	if detail != "" {
		return fmt.Errorf("pgdb: %s: %s: %s", sev, msg, detail)
	}
	return fmt.Errorf("pgdb: %s: %s", sev, msg)
}

// ── value scanning ────────────────────────────────────────────────────────────

func scanValue(col []byte, dest interface{}) error {
	switch d := dest.(type) {
	case *string:
		if col == nil {
			*d = ""
		} else {
			*d = string(col)
		}
	case **string:
		if col == nil {
			*d = nil
		} else {
			s := string(col)
			*d = &s
		}
	case *[]byte:
		if col == nil {
			*d = nil
		} else {
			cp := make([]byte, len(col))
			copy(cp, col)
			*d = cp
		}
	case *int64:
		if col == nil {
			*d = 0
		} else {
			n, err := strconv.ParseInt(strings.TrimSpace(string(col)), 10, 64)
			if err != nil {
				return err
			}
			*d = n
		}
	case **int64:
		if col == nil {
			*d = nil
		} else {
			n, err := strconv.ParseInt(strings.TrimSpace(string(col)), 10, 64)
			if err != nil {
				return err
			}
			*d = &n
		}
	case *int:
		if col == nil {
			*d = 0
		} else {
			n, err := strconv.Atoi(strings.TrimSpace(string(col)))
			if err != nil {
				return err
			}
			*d = n
		}
	case *bool:
		if col == nil {
			*d = false
		} else {
			s := strings.TrimSpace(string(col))
			*d = s == "t" || s == "true" || s == "1" || s == "yes" || s == "on"
		}
	case *time.Time:
		if col == nil {
			*d = time.Time{}
		} else {
			t, err := parseTimestamp(string(col))
			if err != nil {
				return err
			}
			*d = t
		}
	case *json.RawMessage:
		if col == nil {
			*d = nil
		} else {
			cp := make([]byte, len(col))
			copy(cp, col)
			*d = cp
		}
	case *interface{}:
		if col == nil {
			*d = nil
		} else {
			*d = string(col)
		}
	default:
		return fmt.Errorf("unsupported dest type %T", dest)
	}
	return nil
}

// parseTimestamp tries several PostgreSQL timestamp formats.
func parseTimestamp(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999 UTC",
		"2006-01-02 15:04:05 UTC",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp %q", s)
}

// ── SQL quoting ────────────────────────────────────────────────────────────────

// QuoteLiteral escapes a string for safe inclusion in a SQL literal.
// It wraps the value in single quotes and escapes any embedded single quotes.
func QuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// QuoteNullable returns "NULL" for an empty string, otherwise QuoteLiteral(s).
func QuoteNullable(s string) string {
	if s == "" {
		return "NULL"
	}
	return QuoteLiteral(s)
}

// ── misc ──────────────────────────────────────────────────────────────────────

func appendInt32(b []byte, v int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(v))
	return append(b, buf[:]...)
}

func appendString(b []byte, s string) []byte {
	b = append(b, []byte(s)...)
	return append(b, 0)
}

func md5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := fmt.Sprintf("%x", inner)
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return "md5" + fmt.Sprintf("%x", outer)
}
