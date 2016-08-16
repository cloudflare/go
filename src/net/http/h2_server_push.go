package http

import (
	"net/url"
	"regexp"
	"strings"
)

const maxPushId = 300

var pushPromiseRe *regexp.Regexp

var pushPromiseHeaders = []string{
	"cache-control",
	"user-agent",
	"accept-encoding",
	"accept-language",
	"cookie",
}

var defaultPushPriorities = map[string]uint8{
	"image":  5,
	"script": 25,
	"style":  50,
}

type pushHint struct {
	uri, contentType string
}

func init() {
	pushPromiseRe, _ = regexp.Compile("(?i)" +
		"^\\s*(?:" +
		"<" +
		"([^>]*)" + ">" + "\\s*" + "[;?]" +
		"(?:.*?)" + "\\s*rel\\s*=\\s*(\\w*)" + ";?" +
		"(?:.*?)" + "(?:\\s*as\\s*=\\s*(\\w*))?" + ";?" +
		")")
	pushPromiseRe.Longest()
}

func derivePushHints(h string) []*pushHint {
	links := strings.Split(h, ",")
	ret := make([]*pushHint, 0)

	for _, l := range links {
		if !strings.HasSuffix(l, "nopush") && !strings.Contains(l, "nopush;") {
			match := pushPromiseRe.FindStringSubmatch(l)
			if len(match) >= 3 && match[2] == "preload" {
				pushUri, err := url.Parse(match[1])
				if err == nil && pushUri.Scheme == "" && pushUri.Host == "" {
					ret = append(ret, &pushHint{
						uri:         pushUri.String(),
						contentType: match[3],
					})
				}
			}
		}
	}
	return ret
}

func formatDebugEntry(in string) string {
	if len(in) <= 50 {
		return "<" + in + ">"
	} else {
		return "<" + in[0:25] + "..." + in[len(in)-25:] + ">"
	}
}

func (f *http2PushPromiseParam) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	http2encKV(enc, ":authority", f.authority)
	http2encKV(enc, ":method", "GET")
	http2encKV(enc, ":scheme", "https")
	http2encKV(enc, ":path", f.uri)

	for k, vv := range f.headers {
		k = strings.ToLower(k)
		for _, v := range vv {
			http2encKV(enc, k, v)
		}
	}

	f.BlockFragment = buf.Bytes()

	f.sc.processPushPromise(f)

	return ctx.Framer().WritePushPromise(*f)
}

func (sc *http2serverConn) processPushPromise(f *http2PushPromiseParam) error {
	sc.serveG.check()
	id := f.PromiseID
	if sc.inGoAway {
		return nil
	}

	ctx, cancelCtx := http2contextWithCancel(sc.baseCtx)
	st := &http2stream{
		sc:        sc,
		id:        id,
		state:     http2stateHalfClosedRemote,
		ctx:       ctx,
		cancelCtx: cancelCtx,
		parent:    sc.streams[f.StreamID],
		weight:    f.weight,
	}
	st.cw.Init()

	st.flow.conn = &sc.flow
	st.flow.add(sc.initialWindowSize)
	st.inflow.conn = &sc.inflow
	st.inflow.add(http2initialWindowSize)

	sc.streams[id] = st

	rw, req, err := sc.newWriterAndRequestForPromise(st, f)
	if err != nil {
		return err
	}

	handler := sc.handler.ServeHTTP
	if err := http2checkValidHTTP2Request(req); err != nil {
		handler = http2new400Handler(err)
	}

	go sc.runHandler(rw, req, handler)
	return nil
}

func (sc *http2serverConn) newWriterAndRequestForPromise(st *http2stream, f *http2PushPromiseParam) (*http2responseWriter, *Request, error) {
	tlsState := sc.tlsState
	body := &http2requestBody{
		conn:          sc,
		stream:        st,
		needsContinue: false,
	}

	pushUri, _ := url.Parse(f.uri)

	req := &Request{
		Method:     "GET",
		URL:        pushUri,
		RemoteAddr: sc.remoteAddrStr,
		Header:     f.headers,
		RequestURI: f.uri,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		TLS:        tlsState,
		Host:       f.authority,
		Body:       body,
		Trailer:    nil,
	}
	req = http2requestWithContext(req, st.ctx)
	rws := http2responseWriterStatePool.Get().(*http2responseWriterState)
	bwSave := rws.bw
	*rws = http2responseWriterState{}
	rws.conn = sc
	rws.bw = bwSave
	rws.bw.Reset(http2chunkWriter{rws})
	rws.stream = st
	rws.req = req
	rws.body = body

	rw := &http2responseWriter{rws: rws}

	return rw, req, nil
}
