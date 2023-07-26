package httpproxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func Handshake(rw io.ReadWriter) (socks.Addr, error) {
	var buf bytes.Buffer
	req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(rw, &buf))) // TeeReader keeps a copy of data read in case it's a plain http req
	if err != nil {
		return nil, err
	}

	/**
	 * for plain http://
	 *
	 * GET /ip HTTP/1.1
	 * Host: httpbin.org
	 * User-Agent: curl/7.79.1
	 * Accept: &#42;/&#42;
	 * Proxy-Connection: Keep-Alive
	 * content-length: 0
	 */
	if req.Method != "CONNECT" {
		target := req.Host
		if !strings.Contains(target, ":") {
			target = target + ":80"
		}
		addr := socks.ParseAddr(target)

		data := buf.Bytes()

		nAddr := len(addr)
		nData := len(data)
		addrWithData := make([]byte, nAddr+nData)
		copy(addrWithData[:nAddr], addr)
		copy(addrWithData[nAddr:], data)

		return addrWithData, nil
	}

	/**
	 * for tcp/ssl/tls, including https://
	 *
	 * CONNECT streamline.t-mobile.com:22 HTTP/1.1
	 * User-Agent: curl/7.79.1
	 */
	rw.Write([]byte("HTTP/1.1 200 Connection Established\r\n" +
		"Proxy-agent: Golang-Proxy\r\n" +
		"\r\n"))
	target := req.RequestURI
	addr := socks.ParseAddr(target)

	return addr, nil
}
