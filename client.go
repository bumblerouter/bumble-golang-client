package client

import (
	"bumbleserver.org/common/envelope"
	"bumbleserver.org/common/key"
	"bumbleserver.org/common/message"
	"bumbleserver.org/common/peer"
	"code.google.com/p/go.net/websocket"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
)

type Client struct {
	peer                     *peer.Peer
	isAuthenticated          bool
	websocket                *websocket.Conn
	privateKey               *rsa.PrivateKey
	onConnectCallback        func(*Client)
	onDisconnectCallback     func(*Client)
	onAuthenticationCallback func(*Client, bool)
	onMessageCallback        func(*Client, *envelope.Envelope, *message.Header)
	myRouter                 *peer.Peer
	hostOverride             string
}

type Config struct {
	Name             string
	PrivateKey       *rsa.PrivateKey
	OnConnect        func(*Client)
	OnDisconnect     func(*Client)
	OnAuthentication func(*Client, bool)
	OnMessage        func(*Client, *envelope.Envelope, *message.Header)
	HostOverride     string
}

func NewClient(config *Config) *Client {
	c := new(Client)
	c.peer = peer.NewFromString(config.Name)
	c.isAuthenticated = false
	c.privateKey = config.PrivateKey
	c.onConnectCallback = config.OnConnect
	c.onDisconnectCallback = config.OnDisconnect
	c.onAuthenticationCallback = config.OnAuthentication
	c.onMessageCallback = config.OnMessage
	c.hostOverride = config.HostOverride
	return c
}

func (c *Client) Connect() error {
	if c.privateKey == nil {
		return errors.New("private key missing")
	}

	pubkey := c.peer.PublicKey()
	if pubkey == nil {
		publicKeyURL, err := c.peer.PublicKeyURL()
		if err != nil {
			fmt.Printf("Unable to locate your public key in the public key store, likely because of this error: %s\n\n", err)
		} else {
			fmt.Printf("Unable to locate your public key in the public key store.\n\nI expected to find the following data stored at %s\n\n%s\n", publicKeyURL, key.PublicKeyToPEM(c.privateKey.PublicKey))
		}
		return errors.New("public key not in public key store")
	}

	if pubkey.N.Cmp(c.privateKey.PublicKey.N) != 0 {
		publicKeyURL, _ := c.peer.PublicKeyURL()
		fmt.Printf("The global public key store has a public key that doesn't match my own public key stored locally.\n\nI expected to find the following data stored at %s\n\n%s\n", publicKeyURL, key.PublicKeyToPEM(c.privateKey.PublicKey))
		return errors.New("public key does not match the key in the public key store")
	}

	var addrs []*net.SRV
	var err error

	if c.hostOverride == "" {
		_, addrs, err = net.LookupSRV("bumble-client", "tcp", c.peer.Domain)
		if err != nil {
			return err
		}
	} else {
		parts := strings.Split(c.hostOverride, ":")
		port, _ := strconv.ParseUint(parts[1], 10, 0)
		addrs = append(addrs, &net.SRV{
			Target:   parts[0],
			Port:     uint16(port),
			Priority: 0,
			Weight:   0,
		})
	}

	var u *url.URL
	for _, addr := range addrs {
		u = new(url.URL)
		u.Host = strings.Replace(fmt.Sprintf("%s:%v", addr.Target, addr.Port), ".:", ":", 1)
		u.Scheme = "wss"
		u.Path = "/bumble-client"
		fmt.Printf("Connecting to [%s].\n", u.String())
		var config *websocket.Config
		config, err = websocket.NewConfig(u.String(), u.String())
		config.TlsConfig = &tls.Config{
			InsecureSkipVerify: true, // FIXME: this should not be used in production!
		}
		ws, err := websocket.DialConfig(config)
		if err != nil {
			fmt.Printf("Failed to connect to [%s] due to: %s\n", u.String(), err.Error())
			continue
		}
		c.websocket = ws
		c.onConnect(u)
		break
	}
	if c.websocket == nil {
		return errors.New("unable to connect to any servers")
	}

	incoming := make(chan *envelope.Envelope)
	disconnected := make(chan bool)
	go peerEnvelopeReceiver(c.websocket, incoming, disconnected)

	for {
		// fmt.Println("LOOP")
		select {
		case <-disconnected:
			// fmt.Printf("ROUTER-PEER-DISCONNECTION: %s\n", p)
			c.onDisconnect(u)
			return errors.New("got disconnected")
		case e := <-incoming:
			// fmt.Printf("RECEIVED ENVELOPE: %s\n", env)
			if e.GetFrom() == nil { // all envelopes have a sender
				continue
			}

			if c.myRouter == nil && e.GetTo() == nil {
				c.myRouter = e.GetFrom()
			}

			fromMyRouter := (e.GetFrom().String() == c.myRouter.String())          // it's from my router before I have a name
			isForMe := (e.GetTo() != nil && e.GetTo().String() == c.peer.String()) // is this directed at me?
			if fromMyRouter || isForMe {
				err := key.VerifyBytesFromString(e.GetFrom().PublicKey(), []byte(e.GetMessageRaw()), e.GetSignature())
				if err != nil {
					fmt.Printf("DIRECT-RECEIVED-MESSAGE-VERIFICATION-ERROR: %s\n", err)
					continue
				}

				m := e.GetMessage(c.privateKey)

				messageHeader, err := message.HeaderParse(m)
				if err != nil {
					fmt.Printf("DIRECT-RECEIVED-MESSAGEHEADER-PARSE-ERROR: %s\n", err)
					continue
				}

				if messageHeader.GetFrom().String() != e.GetFrom().String() {
					// envelope from field doesn't match the message, do something? FIXME
					continue
				}

				if e.GetTo() == nil && fromMyRouter && messageHeader.GetCode() == message.CODE_AUTHENTICATE {
					msg := message.NewGeneric(message.CODE_AUTHENTICATION)
					msg.SetTo(e.GetFrom())
					msg.SetInfo(e.GetSignature())
					c.OriginateMessage(msg)
					continue
				}

				if fromMyRouter && messageHeader.GetType() == message.TYPE_GENERIC && messageHeader.GetCode() == message.CODE_AUTHENTICATIONRESULT {
					gen, err := message.GenericParse(m)
					if err == nil {
						c.isAuthenticated = gen.Success
						c.onAuthentication(c.isAuthenticated)
					}
					continue
				}

				c.onMessage(e, messageHeader)
			}
		}
	}

	return nil
}

func (c *Client) onConnect(u *url.URL) {
	c.isAuthenticated = false
	//fmt.Printf("Connected to [%s].\n", u.String())
	go c.onConnectCallback(c)
}

func (c *Client) onDisconnect(u *url.URL) {
	c.isAuthenticated = false
	//fmt.Printf("Disconnected from [%s].\n", u.String())
	go c.onDisconnectCallback(c)
}

func (c *Client) onMessage(e *envelope.Envelope, m *message.Header) {
	//fmt.Printf("Envelope from [%s]:  %s\n", e.GetFrom().String(), e)
	go c.onMessageCallback(c, e, m)
}

func (c *Client) onAuthentication(s bool) {
	//fmt.Printf("Authenticated?  %t\n", s)
	go c.onAuthenticationCallback(c, s)
}

func peerEnvelopeReceiver(ws *websocket.Conn, incoming chan *envelope.Envelope, disconnected chan bool) {
	// fmt.Println("PER ENTRY")
	// defer fmt.Println("PER EXIT")
	for {
		var env envelope.Envelope
		err := websocket.JSON.Receive(ws, &env)
		if err == nil {
			incoming <- &env
			continue
		}
		if err == io.EOF || err == syscall.EINVAL || err == syscall.ECONNRESET { // peer disconnected (FIXME: want to get proper test for "read tcp ... use of closed network connection" error)
			disconnected <- true
			break
		}
		if err != nil {
			fmt.Printf("PER ERR: [[[ WARNING: UNHANDLED ERROR ]]] %v\n", err)
			disconnected <- true
			break
		}
	}
}

func (c *Client) Myself() *peer.Peer {
	return c.peer
}

func (c *Client) OriginateMessage(msg message.Message) (signature string, err error) {
	msg.SetFrom(c.peer)
	env, err := envelope.Package(msg, c.privateKey)
	if err != nil {
		fmt.Printf("ORIGINATEMESSAGE-PACKAGE ERROR: %s\n", err.Error())
		return
	}
	signature = env.GetSignature()
	err = websocket.JSON.Send(c.websocket, env)
	if err != nil {
		fmt.Printf("ORIGINATEMESSAGE-JSON-SEND ERROR: %s\n", err.Error())
		return
	}
	return
}
