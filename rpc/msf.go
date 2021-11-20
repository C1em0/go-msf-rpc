package rpc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"gopkg.in/vmihailenco/msgpack.v2"
)

type Metasploit struct {
	host  string
	port  int
	user  string
	pass  string
	ssl   bool
	token string
}

type ErrorRes struct {
	Error        bool   `msgpack:"error,omitempty"`
	ErrorClass   string `msgpack:"error_class,omitempty"`
	ErrorMessage string `msgpack:"error_message,omitempty"`
}

func New(host string, port int, user, pass string, ssl bool) (*Metasploit, error) {
	msf := &Metasploit{
		host: host,
		port: port,
		user: user,
		pass: pass,
		ssl:  ssl,
	}

	if err := msf.Login(); err != nil {
		return nil, err
	}

	return msf, nil
}

func (msf *Metasploit) send(req interface{}, res interface{}) error {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(req)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dest := fmt.Sprintf("http://%s:%d/api", msf.host, msf.port)
	response, err := http.Post(dest, "binary/message-pack", buf)
	// responseBytes, _ := httputil.DumpResponse(response, true)
	// log.Printf("Response dump: %s\n", string(responseBytes))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 200:
		if err := msgpack.NewDecoder(response.Body).Decode(&res); err != nil {
			return err
		}
		buf.Reset()
		return nil
	case 500:
		var errRes ErrorRes
		if err := msgpack.NewDecoder(response.Body).Decode(&errRes); err != nil {
			return err
		}
		return errors.New(fmt.Sprintf("%t %s %s\n", errRes.Error, errRes.ErrorClass, errRes.ErrorMessage))
	case 401:
		return errors.New(fmt.Sprintf("The authentication credentials supplied were not valid"))
	case 403:
		return errors.New(fmt.Sprintf("The authentication credentials supplied were not granted access to the resource"))
	case 404:
		return errors.New(fmt.Sprintf("The request was sent to an invalid URI"))
	default:
		return errors.New(response.Status)
	}
}
