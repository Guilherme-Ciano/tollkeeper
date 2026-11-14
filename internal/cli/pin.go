package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
)

var (
	ErrPinsPending = errors.New("tools with unapproved definitions")
	ErrUnknownPin  = errors.New("tool not in the gateway catalog")
	ErrNoSelection = errors.New("name the tools to approve or pass --all")
	ErrNotApproved = errors.New("approval declined")
)

const (
	defaultAdminURL = "http://127.0.0.1:9090"
	adminTokenEnv   = "TOLLKEEPER_ADMIN_TOKEN"
)

type adminClient struct {
	base  string
	token string
}

func (c adminClient) report(ctx context.Context) (pin.Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.base, "/")+"/pins", http.NoBody)
	if err != nil {
		return pin.Report{}, fmt.Errorf("pin report request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return pin.Report{}, fmt.Errorf("fetch pin report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pin.Report{}, fmt.Errorf("fetch pin report: status %d", resp.StatusCode)
	}
	var r pin.Report
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&r); err != nil {
		return pin.Report{}, fmt.Errorf("decode pin report: %w", err)
	}
	return r, nil
}

func adminFlags(cmd *cobra.Command, c *adminClient) {
	cmd.Flags().StringVar(&c.base, "admin", defaultAdminURL, "gateway admin base URL")
	cmd.Flags().StringVar(&c.token, "token", os.Getenv(adminTokenEnv),
		"bearer token for the admin pin report (default from "+adminTokenEnv+")")
}

func pinCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pin", Short: "Review and approve upstream tool definitions"}
	cmd.AddCommand(pinStatusCmd(), pinApproveCmd())
	return cmd
}

func pinStatusCmd() *cobra.Command {
	var admin adminClient
	var check bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List catalog tools and whether their current definition is approved",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := admin.report(cmd.Context())
			if err != nil {
				return err
			}
			pending, err := printStatus(cmd.OutOrStdout(), r)
			if err != nil {
				return err
			}
			if check && pending > 0 {
				return fmt.Errorf("%w: %d", ErrPinsPending, pending)
			}
			return nil
		},
	}
	adminFlags(cmd, &admin)
	cmd.Flags().BoolVar(&check, "check", false, "exit non-zero when any tool is not approved")
	return cmd
}

func printStatus(w io.Writer, r pin.Report) (int, error) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	pending := 0
	if _, err := fmt.Fprintf(tw, "STATUS\tTOOL\tUPSTREAM\tPIN\n"); err != nil {
		return 0, fmt.Errorf("write output: %w", err)
	}
	for i := range r.Tools {
		t := &r.Tools[i]
		if t.Status != pin.StatusApproved {
			pending++
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			t.Status, safe(t.Name), safe(t.Upstream), shortPin(t.Pin)); err != nil {
			return 0, fmt.Errorf("write output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return 0, fmt.Errorf("write output: %w", err)
	}
	return pending, printf(w, "mode %s, %d of %d tools not approved\n", safe(string(r.Mode)), pending, len(r.Tools))
}

func shortPin(p string) string {
	if len(p) > 12 {
		return safe(p[:12])
	}
	return safe(p)
}

func invisible(r rune) bool {
	switch {
	case r == '\t':
		return false
	case unicode.IsControl(r):
		return true
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2069, r == 0xFEFF:
		return true
	default:
		return !unicode.IsPrint(r) && !unicode.IsSpace(r)
	}
}

func safe(s string) string {
	if !strings.ContainsFunc(s, invisible) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if invisible(r) {
			b.WriteString(`\u{` + strconv.FormatInt(int64(r), 16) + `}`)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

type approveOptions struct {
	admin adminClient
	file  string
	by    string
	all   bool
	prune bool
	yes   bool
	tools []string
	in    io.Reader
	now   func() time.Time
}

func pinApproveCmd() *cobra.Command {
	opts := approveOptions{now: time.Now}
	cmd := &cobra.Command{
		Use:   "approve [tool...]",
		Short: "Show each definition change, confirm it, and record it in the lockfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.tools = args
			opts.in = cmd.InOrStdin()
			r, err := opts.admin.report(cmd.Context())
			if err != nil {
				return err
			}
			return approve(cmd.OutOrStdout(), r, opts)
		},
	}
	adminFlags(cmd, &opts.admin)
	cmd.Flags().StringVarP(&opts.file, "file", "f", "pins.json", "pin lockfile the gateway reads (pinning.file)")
	cmd.Flags().StringVar(&opts.by, "by", os.Getenv("USER"), "approver recorded in the lockfile")
	cmd.Flags().BoolVar(&opts.all, "all", false, "review every tool that is new or changed")
	cmd.Flags().BoolVar(&opts.prune, "prune", false, "drop lockfile entries for tools no longer in the catalog")
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "approve without asking, after printing each change")
	return cmd
}

func approve(w io.Writer, r pin.Report, opts approveOptions) error {
	lock, version, err := pin.ReadVersioned(opts.file)
	if err != nil {
		return err
	}
	selected, err := selectTools(r, opts)
	if err != nil {
		return err
	}
	answers := bufio.NewReader(opts.in)
	approved := 0
	for i := range selected {
		t := &selected[i]
		if err := t.Verify(); err != nil {
			return err
		}
		if lock.Status(t.Tool()) == pin.StatusApproved {
			continue
		}
		if err := printChange(w, t, lock); err != nil {
			return err
		}
		ok, err := confirm(w, answers, t.Name, opts.yes)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		lock = lock.Approve(t.Tool(), opts.by, opts.now())
		approved++
	}
	pruned := 0
	if opts.prune {
		pruned = pruneMissing(lock, r)
	}
	if approved == 0 && pruned == 0 {
		return printf(w, "nothing approved\n")
	}
	if err := pin.WriteIfUnchanged(opts.file, lock, version); err != nil {
		return fmt.Errorf("%w; run pin approve again", err)
	}
	return printf(w, "approved %d, pruned %d, wrote %s\n", approved, pruned, opts.file)
}

func confirm(w io.Writer, in *bufio.Reader, name string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if err := printf(w, "approve %s? [y/N] ", safe(name)); err != nil {
		return false, err
	}
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read answer: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if errors.Is(err, io.EOF) && answer == "" {
		return false, fmt.Errorf("%w: no answer for %s; pass --yes for non-interactive use", ErrNotApproved, name)
	}
	return answer == "y" || answer == "yes", nil
}

func selectTools(r pin.Report, opts approveOptions) ([]pin.ToolReport, error) {
	if len(opts.tools) > 0 {
		byName := make(map[string]int, len(r.Tools))
		for i := range r.Tools {
			byName[r.Tools[i].Name] = i
		}
		out := make([]pin.ToolReport, 0, len(opts.tools))
		for _, name := range opts.tools {
			i, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrUnknownPin, name)
			}
			out = append(out, r.Tools[i])
		}
		return out, nil
	}
	if !opts.all {
		return nil, ErrNoSelection
	}
	var out []pin.ToolReport
	for i := range r.Tools {
		if r.Tools[i].Status != pin.StatusApproved {
			out = append(out, r.Tools[i])
		}
	}
	return out, nil
}

func pruneMissing(lock pin.Lockfile, r pin.Report) int {
	present := make(map[string]bool, len(r.Tools))
	for i := range r.Tools {
		present[r.Tools[i].Name] = true
	}
	pruned := 0
	for _, name := range lock.Names() {
		if !present[name] {
			delete(lock.Tools, name)
			pruned++
		}
	}
	return pruned
}

func pretty(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return strings.Split(string(raw), "\n")
	}
	return strings.Split(buf.String(), "\n")
}

func printChange(w io.Writer, t *pin.ToolReport, lock pin.Lockfile) error {
	status := lock.Status(t.Tool())
	if err := printf(
		w,
		"\n%s %s (upstream %s)\n  pin %s\n",
		status,
		safe(t.Name),
		safe(t.Upstream),
		safe(t.Pin),
	); err != nil {
		return err
	}
	var before []string
	if prev, ok := lock.Tools[t.Name]; ok {
		before = pretty(prev.Definition)
		if len(before) == 0 {
			before = pretty(prev.Descriptor)
		}
		if err := printf(w, "  was %s\n", safe(prev.Pin)); err != nil {
			return err
		}
	}
	for _, line := range unifiedDiff(before, pretty(t.Definition)) {
		if err := printf(w, "  %s\n", safe(line)); err != nil {
			return err
		}
	}
	return nil
}

func unifiedDiff(a, b []string) []string {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	out := make([]string, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, "  "+a[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "- "+a[i])
			i++
		default:
			out = append(out, "+ "+b[j])
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, "- "+a[i])
	}
	for ; j < m; j++ {
		out = append(out, "+ "+b[j])
	}
	return out
}
