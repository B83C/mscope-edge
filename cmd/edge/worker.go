package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/B83C/mscope-edge/pkg/control"
	"github.com/coder/websocket"
)

func (e *edge) workerWS() *websocket.Conn {
	e.workerWSMu.Lock()
	defer e.workerWSMu.Unlock()
	return e.workerWSConn
}

func (e *edge) setWorkerWS(c *websocket.Conn) {
	e.workerWSMu.Lock()
	defer e.workerWSMu.Unlock()
	if e.workerWSConn != nil {
		e.workerWSConn.Close(websocket.StatusNormalClosure, "reconnect")
	}
	e.workerWSConn = c
}

func (e *edge) workerHTTPClient() *http.Client {
	if e.workerTLS != nil {
		return &http.Client{
			Transport: &http.Transport{TLSClientConfig: e.workerTLS},
			Timeout:   10 * time.Second,
		}
	}
	return http.DefaultClient
}

func (e *edge) bootstrapFromWorker(ctx context.Context) error {
	hc := e.workerHTTPClient()
	resp, err := hc.Get(e.workerURL + "/edge/" + e.workerDeviceID)
	if err != nil {
		return fmt.Errorf("worker GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("worker status %d", resp.StatusCode)
	}
	var data struct {
		Config *control.ServerConfig `json:"config"`
		Cert   *struct {
			DER string `json:"der"`
			Key string `json:"key"`
			Pin string `json:"pin"`
		} `json:"cert"`
		Grants []control.UserGrant `json:"grants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if data.Config != nil {
		cp := control.ConfigPayload{Config: *data.Config}
		if err := e.cfgSrc.Apply(cp); err == nil {
			e.maybeBuildServer(ctx)
		}
	}
	if data.Cert != nil && data.Cert.DER != "" {
		certDER, _ := base64.StdEncoding.DecodeString(data.Cert.DER)
		keyDER, _ := base64.StdEncoding.DecodeString(data.Cert.Key)
		if len(certDER) > 0 && len(keyDER) > 0 {
			e.vault.InstallFromDER(certDER, keyDER)
			e.maybeBuildServer(ctx)
		}
	}
	if len(data.Grants) > 0 {
		e.auth.Apply(control.GrantsPayload{
			Grants: data.Grants,
		})
	}
	log.Printf("worker: bootstrap done config=%v cert=%v grants=%d",
		data.Config != nil, data.Cert != nil && data.Cert.DER != "", len(data.Grants))
	return nil
}

func (e *edge) workerWSLoop(ctx context.Context, replacedCh chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		u := strings.Replace(e.workerURL, "https://", "wss://", 1)
		u = strings.Replace(u, "http://", "ws://", 1)
		u += "/ws"

		var wsOpts *websocket.DialOptions
		if e.workerTLS != nil {
			wsOpts = &websocket.DialOptions{
				HTTPClient: &http.Client{
					Transport: &http.Transport{TLSClientConfig: e.workerTLS},
				},
			}
		}
		c, _, err := websocket.Dial(ctx, u, wsOpts)
		if err != nil {
			log.Printf("worker: ws dial error: %v (retry in 5s)", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		e.setWorkerWS(c)
		log.Printf("worker: ws connected")

		ipv4, ipv6 := "", ""
		for _, ip := range e.publicIPs {
			if net.ParseIP(ip).To4() != nil {
				ipv4 = ip
			} else {
				ipv6 = ip
			}
		}
		joinBody, _ := json.Marshal(map[string]any{
			"type": "join", "deviceID": e.workerDeviceID, "name": e.edgeID, "version": version,
			"public_ipv4": ipv4, "public_ipv6": ipv6,
			"started_at": time.Now().UnixNano(),
		})
		c.Write(ctx, websocket.MessageText, joinBody)

		for {
			_, msg, err := c.Read(ctx)
			if err != nil {
				log.Printf("worker: ws read error: %v (reconnecting)", err)
				e.setWorkerWS(nil)
				var ce websocket.CloseError
				if errors.As(err, &ce) && ce.Code == websocket.StatusPolicyViolation {
					close(replacedCh)
					return
				}
				break
			}
			var data struct {
				Type   string                `json:"type"`
				Config *control.ServerConfig `json:"config"`
				Grants []control.UserGrant   `json:"grants"`
				UserID string                `json:"userID"`
				Count  int                   `json:"count"`
				OK     bool                  `json:"ok"`
				Cert   *struct {
					DER string `json:"der"`
					Key string `json:"key"`
					Pin string `json:"pin"`
				} `json:"cert"`
			}
			if err := json.Unmarshal(msg, &data); err != nil {
				continue
			}
			switch data.Type {
			case "config":
				if data.Config != nil {
					e.cfgSrc.Apply(control.ConfigPayload{Config: *data.Config})
					e.maybeBuildServer(ctx)
				}
				if data.Cert != nil {
					certDER, _ := base64.StdEncoding.DecodeString(data.Cert.DER)
					keyDER, _ := base64.StdEncoding.DecodeString(data.Cert.Key)
					if len(certDER) > 0 && len(keyDER) > 0 {
						e.vault.InstallFromDER(certDER, keyDER)
						e.maybeBuildServer(ctx)
					}
				}
				if len(data.Grants) > 0 {
					e.auth.Apply(control.GrantsPayload{
						Grants: data.Grants,
					})
				}
			case "connect_result":
				if !data.OK {
					log.Printf("worker: user %s over limit, kicking", data.UserID)
					e.auth.KickUser(data.UserID)
				}
			case "session_update":
				if data.UserID != "" {
					max, _ := e.auth.UserMax(data.UserID)
					if max > 0 && data.Count < max {
						e.auth.UnblockUser(data.UserID)
					}
				}
			}
		}
	}
}
