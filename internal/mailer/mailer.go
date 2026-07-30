package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidConfig  = errors.New("invalid SMTP configuration")
	ErrInvalidMessage = errors.New("invalid email message")
)

type TLSMode string

const (
	TLSImplicit TLSMode = "implicit"
	TLSStartTLS TLSMode = "starttls"
)

type Config struct {
	Host        string
	Port        int
	Username    string
	Password    string
	TLSMode     TLSMode
	FromAddress string
	FromName    string
}

func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Host) != ""
}

func (c Config) Validate() error {
	if !c.Enabled() {
		if c.Port != 0 ||
			strings.TrimSpace(c.Username) != "" ||
			c.Password != "" ||
			strings.TrimSpace(c.FromAddress) != "" {
			return fmt.Errorf("%w: SMTP host is required when SMTP settings are configured", ErrInvalidConfig)
		}
		return nil
	}
	host := strings.TrimSpace(c.Host)
	if host == "" ||
		strings.ContainsAny(host, "/\\ \t\r\n") ||
		(strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return fmt.Errorf("%w: SMTP host must be a hostname or IP address without a port", ErrInvalidConfig)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%w: SMTP port must be between 1 and 65535", ErrInvalidConfig)
	}
	if c.TLSMode != TLSImplicit && c.TLSMode != TLSStartTLS {
		return fmt.Errorf("%w: SMTP TLS mode must be implicit or starttls", ErrInvalidConfig)
	}
	if (strings.TrimSpace(c.Username) == "") != (c.Password == "") {
		return fmt.Errorf("%w: SMTP username and password must be configured together", ErrInvalidConfig)
	}
	if containsHeaderControl(c.Username) {
		return fmt.Errorf("%w: SMTP username contains control characters", ErrInvalidConfig)
	}
	if strings.ContainsRune(c.Password, '\x00') {
		return fmt.Errorf("%w: SMTP password contains a NUL character", ErrInvalidConfig)
	}
	if _, err := normalizeAddress(c.FromAddress); err != nil {
		return fmt.Errorf("%w: invalid from address", ErrInvalidConfig)
	}
	name := strings.TrimSpace(c.FromName)
	if name == "" || utf8.RuneCountInString(name) > 128 || containsHeaderControl(name) {
		return fmt.Errorf("%w: from name must contain 1-128 safe characters", ErrInvalidConfig)
	}
	return nil
}

func (c Config) address() string {
	return net.JoinHostPort(strings.TrimSpace(c.Host), strconv.Itoa(c.Port))
}

type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

func (m Message) Validate() error {
	if _, err := normalizeAddress(m.To); err != nil {
		return fmt.Errorf("%w: invalid recipient", ErrInvalidMessage)
	}
	subject := strings.TrimSpace(m.Subject)
	if subject == "" || utf8.RuneCountInString(subject) > 200 || containsHeaderControl(subject) {
		return fmt.Errorf("%w: subject must contain 1-200 safe characters", ErrInvalidMessage)
	}
	if m.Text == "" && m.HTML == "" {
		return fmt.Errorf("%w: text or HTML body is required", ErrInvalidMessage)
	}
	if len(m.Text)+len(m.HTML) > 1<<20 {
		return fmt.Errorf("%w: message body exceeds 1 MiB", ErrInvalidMessage)
	}
	return nil
}

type Sender interface {
	Send(context.Context, Message) error
}

type SMTP struct {
	config    Config
	tlsConfig *tls.Config
	timeout   time.Duration
	now       func() time.Time
}

func NewSMTP(config Config) (*SMTP, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Enabled() {
		return nil, fmt.Errorf("%w: SMTP is not configured", ErrInvalidConfig)
	}
	host := strings.TrimSpace(config.Host)
	return &SMTP{
		config: config,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		},
		timeout: 10 * time.Second,
		now:     time.Now,
	}, nil
}

func (s *SMTP) Send(ctx context.Context, message Message) error {
	if err := message.Validate(); err != nil {
		return err
	}
	payload, recipient, err := s.buildMessage(message)
	if err != nil {
		return err
	}
	connection, err := s.dial(ctx)
	if err != nil {
		return fmt.Errorf("connect SMTP server: %w", err)
	}
	defer connection.Close()
	if err := setConnectionDeadline(connection, ctx, s.timeout); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(connection, strings.TrimSpace(s.config.Host))
	if err != nil {
		return fmt.Errorf("initialize SMTP client: %w", err)
	}
	defer client.Close()
	if s.config.TLSMode == TLSStartTLS {
		if err := client.StartTLS(s.tlsConfig.Clone()); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if strings.TrimSpace(s.config.Username) != "" {
		auth := encryptedPlainAuth{
			username: strings.TrimSpace(s.config.Username),
			password: s.config.Password,
			host:     strings.TrimSpace(s.config.Host),
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate SMTP client: %w", err)
		}
	}
	from, _ := normalizeAddress(s.config.FromAddress)
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP message: %w", err)
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("quit SMTP session: %w", err)
	}
	return nil
}

type encryptedPlainAuth struct {
	username string
	password string
	host     string
}

func (a encryptedPlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !strings.EqualFold(server.Name, a.host) {
		return "", nil, errors.New("SMTP server identity does not match configured host")
	}
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (encryptedPlainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("SMTP PLAIN authentication requested an unexpected challenge")
	}
	return nil, nil
}

func (s *SMTP) dial(ctx context.Context) (net.Conn, error) {
	address := s.config.address()
	if s.config.TLSMode == TLSImplicit {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: s.timeout},
			Config:    s.tlsConfig.Clone(),
		}
		return dialer.DialContext(ctx, "tcp", address)
	}
	dialer := &net.Dialer{Timeout: s.timeout}
	return dialer.DialContext(ctx, "tcp", address)
}

func (s *SMTP) buildMessage(message Message) ([]byte, string, error) {
	if err := message.Validate(); err != nil {
		return nil, "", err
	}
	from, err := normalizeAddress(s.config.FromAddress)
	if err != nil {
		return nil, "", err
	}
	recipient, err := normalizeAddress(message.To)
	if err != nil {
		return nil, "", err
	}
	var output bytes.Buffer
	fromHeader := (&mail.Address{
		Name:    strings.TrimSpace(s.config.FromName),
		Address: from,
	}).String()
	toHeader := (&mail.Address{Address: recipient}).String()
	messageID, err := newMessageID(from)
	if err != nil {
		return nil, "", fmt.Errorf("create message ID: %w", err)
	}
	writeHeader(&output, "Date", s.now().UTC().Format(time.RFC1123Z))
	writeHeader(&output, "Message-ID", messageID)
	writeHeader(&output, "From", fromHeader)
	writeHeader(&output, "To", toHeader)
	writeHeader(&output, "Subject", mime.QEncoding.Encode("UTF-8", strings.TrimSpace(message.Subject)))
	writeHeader(&output, "MIME-Version", "1.0")
	if message.Text != "" && message.HTML != "" {
		writer := multipart.NewWriter(&output)
		writeHeader(&output, "Content-Type", `multipart/alternative; boundary="`+writer.Boundary()+`"`)
		output.WriteString("\r\n")
		if err := writeMessagePart(writer, "text/plain; charset=UTF-8", message.Text); err != nil {
			return nil, "", err
		}
		if err := writeMessagePart(writer, "text/html; charset=UTF-8", message.HTML); err != nil {
			return nil, "", err
		}
		if err := writer.Close(); err != nil {
			return nil, "", fmt.Errorf("finish multipart email: %w", err)
		}
	} else {
		contentType := "text/plain; charset=UTF-8"
		body := message.Text
		if body == "" {
			contentType = "text/html; charset=UTF-8"
			body = message.HTML
		}
		writeHeader(&output, "Content-Type", contentType)
		writeHeader(&output, "Content-Transfer-Encoding", "quoted-printable")
		output.WriteString("\r\n")
		writer := quotedprintable.NewWriter(&output)
		if _, err := io.WriteString(writer, body); err != nil {
			return nil, "", fmt.Errorf("write email body: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, "", fmt.Errorf("finish email body: %w", err)
		}
	}
	return output.Bytes(), recipient, nil
}

func writeMessagePart(writer *multipart.Writer, contentType, body string) error {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create email part: %w", err)
	}
	encoded := quotedprintable.NewWriter(part)
	if _, err := io.WriteString(encoded, body); err != nil {
		return fmt.Errorf("write email part: %w", err)
	}
	if err := encoded.Close(); err != nil {
		return fmt.Errorf("finish email part: %w", err)
	}
	return nil
}

func writeHeader(output *bytes.Buffer, name, value string) {
	output.WriteString(name)
	output.WriteString(": ")
	output.WriteString(value)
	output.WriteString("\r\n")
}

func normalizeAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || containsHeaderControl(value) {
		return "", errors.New("invalid email address")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(parsed.Address), nil
}

func containsHeaderControl(value string) bool {
	return strings.ContainsAny(value, "\r\n\x00")
}

func newMessageID(from string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	_, domain, ok := strings.Cut(from, "@")
	if !ok || domain == "" {
		return "", errors.New("from address has no domain")
	}
	return "<" + hex.EncodeToString(random) + "@" + domain + ">", nil
}

func setConnectionDeadline(connection net.Conn, ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return connection.SetDeadline(deadline)
}
