package probe

import (
	"context"
	"net/http"
	"sort"
	"sync"

	"github.com/st3fan/mcpeel/internal/auth"
)

type authTraceKey struct{}
type authTrace struct {
	log                     *authLog
	transport, stage, group string
}

func authStage(ctx context.Context, transport, stage, group string) context.Context {
	trace, _ := ctx.Value(authTraceKey{}).(authTrace)
	trace.transport, trace.stage, trace.group = transport, stage, group
	return context.WithValue(ctx, authTraceKey{}, trace)
}

func noAuthTrace(ctx context.Context) context.Context {
	return context.WithValue(ctx, authTraceKey{}, authTrace{})
}

type authEntry struct {
	group       string
	observation auth.Observation
	relevant    bool
}

type authLog struct {
	mu        sync.Mutex
	entries   []*authEntry
	responses map[*http.Response]*authEntry
	resolver  *auth.Resolver
	wg        sync.WaitGroup
}

func newAuthLog(p *Prober) *authLog {
	return &authLog{responses: make(map[*http.Response]*authEntry), resolver: auth.NewResolver(func(ctx context.Context, target string) (*http.Response, error) {
		h := headers("", "", "")
		h.Set("Accept", "application/json")
		r, err, _ := p.exchange(noAuthTrace(ctx), http.MethodGet, target, nil, h, true)
		return r, err
	})}
}

func recordResponse(ctx context.Context, r *http.Response) {
	t, _ := ctx.Value(authTraceKey{}).(authTrace)
	if t.log == nil {
		return
	}
	o := auth.Observe(r, t.transport, t.stage)
	group := t.group
	if group == "" {
		group = o.URL
	}
	relevant := o.HTTPStatus == 401 || o.HTTPStatus == 403 || len(o.RawChallenges) != 0
	e := &authEntry{group: group, observation: o, relevant: relevant}
	t.log.mu.Lock()
	t.log.entries = append(t.log.entries, e)
	t.log.responses[r] = e
	t.log.mu.Unlock()
	if relevant {
		// Metadata work starts at the challenge, so another stalled transport
		// cannot consume the whole deadline before discovery is attempted.
		t.log.wg.Go(func() {
			enriched := t.log.resolver.Enrich(ctx, o)
			t.log.mu.Lock()
			e.observation.Metadata, e.observation.OAuthAdvertised = enriched.Metadata, enriched.OAuthAdvertised
			t.log.mu.Unlock()
		})
	}
}

func markAnonymous(ctx context.Context, r *http.Response) {
	t, _ := ctx.Value(authTraceKey{}).(authTrace)
	if t.log == nil {
		return
	}
	t.log.mu.Lock()
	defer t.log.mu.Unlock()
	if e := t.log.responses[r]; e != nil {
		e.observation.State = auth.AnonymousProbe
	}
}

func recordResponseError(ctx context.Context, r *http.Response, err error, relevant bool) {
	t, _ := ctx.Value(authTraceKey{}).(authTrace)
	if t.log == nil || err == nil {
		return
	}
	t.log.mu.Lock()
	defer t.log.mu.Unlock()
	if e := t.log.responses[r]; e != nil {
		e.observation.Error = err.Error()
		e.relevant = e.relevant || relevant
	}
}

func recordFailure(ctx context.Context, method, endpoint string, err error) {
	t, _ := ctx.Value(authTraceKey{}).(authTrace)
	if t.log == nil {
		return
	}
	group := t.group
	if group == "" {
		group = endpoint
	}
	t.log.mu.Lock()
	t.log.entries = append(t.log.entries, &authEntry{group: group, observation: auth.Observation{
		URL: endpoint, Transport: t.transport, Stage: t.stage, Method: method, State: auth.Unknown, Error: err.Error(),
	}})
	t.log.mu.Unlock()
}

func (l *authLog) finish(findings []Finding, input string) []Finding {
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	byURL := make(map[string]int)
	for i := range findings {
		byURL[findings[i].URL] = i
	}
	// Sort observations independently of goroutine scheduling.
	sort.SliceStable(l.entries, func(i, j int) bool {
		a, b := l.entries[i].observation, l.entries[j].observation
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		if a.Transport != b.Transport {
			return a.Transport < b.Transport
		}
		return a.Stage < b.Stage
	})
	for _, e := range l.entries {
		if _, exists := byURL[e.group]; !exists && e.relevant {
			byURL[e.group] = len(findings)
			findings = append(findings, Finding{URL: e.group, Transports: []string{}, TransportDetails: map[string]TransportEvidence{}})
		}
	}
	for _, e := range l.entries {
		if i, exists := byURL[e.group]; exists {
			findings[i].Authentication = append(findings[i].Authentication, e.observation.Clone())
		}
	}
	for i := range findings {
		findings[i].Input = input
	}
	return findings
}
