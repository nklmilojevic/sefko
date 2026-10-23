// Package client talks to the sefko agent over its Unix socket.
package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/nklmilojevic/sefko/internal/protocol"
)

// ErrUnreachable wraps every failure to connect to the agent, so callers can
// fall back to reading 1Password directly.
var ErrUnreachable = errors.New("sefko agent is not running")

type Client struct {
	Socket string
	// Timeout bounds a whole request. Fetches can wait for a 1Password
	// approval, so it must exceed the agent's fetch_timeout.
	Timeout time.Duration
}

func New(socket string) *Client {
	return &Client{Socket: socket, Timeout: 90 * time.Second}
}

// Do sends one request and decodes the response. A failed response is
// returned as *protocol.Error.
func (c *Client) Do(req protocol.Request) (*protocol.Response, error) {
	req.V = protocol.Version
	conn, err := net.DialTimeout("unix", c.Socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrUnreachable, c.Socket, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		clear(line)
		if len(line) == 0 {
			return nil, fmt.Errorf("agent closed the connection without answering (refused?): %w", err)
		}
		return nil, fmt.Errorf("read response: %w", err)
	}
	var resp protocol.Response
	err = json.Unmarshal(line, &resp)
	clear(line)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !resp.OK {
		return nil, &protocol.Error{Code: resp.Code, Message: resp.Message}
	}
	return &resp, nil
}

func (c *Client) Get(name string) (string, error) {
	r, err := c.Do(protocol.Request{Op: protocol.OpGet, Name: name})
	if err != nil {
		return "", err
	}
	return r.Value, nil
}

func (c *Client) Refresh(name string) (string, error) {
	r, err := c.Do(protocol.Request{Op: protocol.OpRefresh, Name: name})
	if err != nil {
		return "", err
	}
	return r.Value, nil
}

func (c *Client) Validate(name string) (string, error) {
	r, err := c.Do(protocol.Request{Op: protocol.OpValidate, Name: name})
	if err != nil {
		return "", err
	}
	return r.Result, nil
}

func (c *Client) Lock() error {
	_, err := c.Do(protocol.Request{Op: protocol.OpLock})
	return err
}

func (c *Client) Status() (*protocol.Status, error) {
	r, err := c.Do(protocol.Request{Op: protocol.OpStatus})
	if err != nil {
		return nil, err
	}
	return r.Status, nil
}

func (c *Client) Names() ([]protocol.Name, error) {
	r, err := c.Do(protocol.Request{Op: protocol.OpNames})
	if err != nil {
		return nil, err
	}
	return r.Names, nil
}

func (c *Client) Reload() error {
	_, err := c.Do(protocol.Request{Op: protocol.OpReload})
	return err
}
