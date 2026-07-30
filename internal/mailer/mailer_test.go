package mailer

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestConfigAndMessageValidation(t *testing.T) {
	config := Config{
		Host:        "smtp.example.com",
		Port:        465,
		Username:    "support@example.com",
		Password:    "secret",
		TLSMode:     TLSImplicit,
		FromAddress: "support@example.com",
		FromName:    "Certus Support",
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.FromName = "Certus\r\nBcc: attacker@example.com"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsafe sender name returned %v", err)
	}
	config.FromName = "Certus"
	config.Password = "secret\x00tail"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("password containing NUL returned %v", err)
	}
	message := Message{
		To:      "alice@example.com",
		Subject: "Hello\r\nBcc: attacker@example.com",
		Text:    "test",
	}
	if err := message.Validate(); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unsafe subject returned %v", err)
	}
}

func TestEncryptedPlainAuthSupportsImplicitTLSHost(t *testing.T) {
	auth := encryptedPlainAuth{
		username: "support@example.com",
		password: "secret",
		host:     "smtp.example.com",
	}
	mechanism, initial, err := auth.Start(&smtp.ServerInfo{
		Name: "smtp.example.com",
		TLS:  false,
		Auth: []string{"PLAIN"},
	})
	if err != nil || mechanism != "PLAIN" || string(initial) != "\x00support@example.com\x00secret" {
		t.Fatalf("unexpected implicit TLS auth result: %q %q %v", mechanism, initial, err)
	}
	if _, _, err := auth.Start(&smtp.ServerInfo{Name: "attacker.example.com"}); err == nil {
		t.Fatal("SMTP auth accepted a different server identity")
	}
}

func TestSMTPSendsWithConfigurableSenderName(t *testing.T) {
	for _, mode := range []TLSMode{TLSImplicit, TLSStartTLS} {
		t.Run(string(mode), func(t *testing.T) {
			certificate, roots := testCertificate(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			result := make(chan smtpTestResult, 1)
			go serveTestSMTP(listener, certificate, mode, result)

			port := listener.Addr().(*net.TCPAddr).Port
			sender, err := NewSMTP(Config{
				Host:        "localhost",
				Port:        port,
				Username:    "support@example.com",
				Password:    "top-secret",
				TLSMode:     mode,
				FromAddress: "support@example.com",
				FromName:    "可配置发件名称",
			})
			if err != nil {
				t.Fatal(err)
			}
			sender.tlsConfig.RootCAs = roots
			sender.timeout = 5 * time.Second
			sender.now = func() time.Time {
				return time.Date(2026, 7, 31, 8, 0, 0, 0, time.UTC)
			}
			if err := sender.Send(context.Background(), Message{
				To:      "alice@example.com",
				Subject: "SMTP 测试",
				Text:    "Certus SMTP text body",
				HTML:    "<strong>Certus SMTP HTML body</strong>",
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case received := <-result:
				if received.err != nil {
					t.Fatal(received.err)
				}
				body := string(received.message)
				if !strings.Contains(strings.ToLower(body), "from: =?utf-8?q?") ||
					!strings.Contains(body, "<support@example.com>") ||
					!strings.Contains(body, "multipart/alternative") ||
					!strings.Contains(body, "Certus SMTP text body") ||
					strings.Contains(body, "top-secret") {
					t.Fatalf("unexpected SMTP message:\n%s", body)
				}
				if !received.authenticated {
					t.Fatal("SMTP authentication was not used")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("SMTP test server did not finish")
			}
		})
	}
}

type smtpTestResult struct {
	message       []byte
	authenticated bool
	err           error
}

func serveTestSMTP(
	listener net.Listener,
	certificate tls.Certificate,
	mode TLSMode,
	result chan<- smtpTestResult,
) {
	connection, err := listener.Accept()
	if err != nil {
		result <- smtpTestResult{err: err}
		return
	}
	defer connection.Close()
	tlsActive := false
	if mode == TLSImplicit {
		connection = tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		if err := connection.(*tls.Conn).Handshake(); err != nil {
			result <- smtpTestResult{err: err}
			return
		}
		tlsActive = true
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	if err := smtpReply(writer, "220 localhost ESMTP ready"); err != nil {
		result <- smtpTestResult{err: err}
		return
	}
	authenticated := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			result <- smtpTestResult{err: err}
			return
		}
		command := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(command, "EHLO "):
			if mode == TLSStartTLS && !tlsActive {
				if err := smtpReply(writer, "250-localhost", "250 STARTTLS"); err != nil {
					result <- smtpTestResult{err: err}
					return
				}
			} else {
				if err := smtpReply(writer, "250-localhost", "250 AUTH PLAIN"); err != nil {
					result <- smtpTestResult{err: err}
					return
				}
			}
		case command == "STARTTLS" && mode == TLSStartTLS && !tlsActive:
			if err := smtpReply(writer, "220 Ready to start TLS"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
			tlsConnection := tls.Server(connection, &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsConnection.Handshake(); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
			connection = tlsConnection
			reader = bufio.NewReader(connection)
			writer = bufio.NewWriter(connection)
			tlsActive = true
		case strings.HasPrefix(command, "AUTH PLAIN"):
			authenticated = true
			if err := smtpReply(writer, "235 Authentication successful"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"):
			if err := smtpReply(writer, "250 Sender accepted"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
		case strings.HasPrefix(command, "RCPT TO:"):
			if err := smtpReply(writer, "250 Recipient accepted"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
		case command == "DATA":
			if err := smtpReply(writer, "354 End data with <CR><LF>.<CR><LF>"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
			message, err := textproto.NewReader(reader).ReadDotBytes()
			if err != nil {
				result <- smtpTestResult{err: err}
				return
			}
			if err := smtpReply(writer, "250 Message accepted"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
			result <- smtpTestResult{message: message, authenticated: authenticated}
		case command == "QUIT":
			_ = smtpReply(writer, "221 Bye")
			return
		default:
			if err := smtpReply(writer, "500 Unsupported command"); err != nil {
				result <- smtpTestResult{err: err}
				return
			}
		}
	}
}

func smtpReply(writer *bufio.Writer, lines ...string) error {
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(certificatePEM); !ok {
		t.Fatal("failed to add test certificate")
	}
	return certificate, roots
}
