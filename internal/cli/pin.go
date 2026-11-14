package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
)

var (
	ErrPinsPending = errors.New("tools with unapproved definitions")
	ErrUnknownPin  = errors.New("tool not in the gateway catalog")
	ErrNoSelection = errors.New("name the tools to approve or pass --all")
)

const defaultAdminURL = "http://127.0.0.1:9090"

func fetchReport(ctx context.Context, admin string) (pin.Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(admin, "/")+"/pins", http.NoBody)
	if err != nil {
		return pin.Report{}, fmt.Errorf("pin report request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
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

func pinCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pin", Short: "Review and approve upstream tool definitions"}
	cmd.AddCommand(pinStatusCmd(), pinApproveCmd())
	return cmd
}

func pinStatusCmd() *cobra.Command {
	var admin string
	var check bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List catalog tools and whether their current definition is approved",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := fetchReport(cmd.Context(), admin)
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
	cmd.Flags().StringVar(&admin, "admin", defaultAdminURL, "gateway admin base URL")
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
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Status, t.Name, t.Upstream, shortPin(t.Pin)); err != nil {
			return 0, fmt.Errorf("write output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return 0, fmt.Errorf("write output: %w", err)
	}
	return pending, printf(w, "mode %s, %d of %d tools not approved\n", r.Mode, pending, len(r.Tools))
}

func shortPin(p string) string {
	if len(p) > 12 {
		return p[:12]
	}
	return p
}

type approveOptions struct {
	admin string
	file  string
	by    string
	all   bool
	prune bool
	tools []string
	now   func() time.Time
}

func pinApproveCmd() *cobra.Command {
	opts := approveOptions{now: time.Now}
	cmd := &cobra.Command{
		Use:   "approve [tool...]",
		Short: "Show what changed and record the current definitions as approved in the lockfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.tools = args
			r, err := fetchReport(cmd.Context(), opts.admin)
			if err != nil {
				return err
			}
			return approve(cmd.OutOrStdout(), r, opts)
		},
	}
	cmd.Flags().StringVar(&opts.admin, "admin", defaultAdminURL, "gateway admin base URL")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "pins.json", "pin lockfile the gateway reads (pinning.file)")
	cmd.Flags().StringVar(&opts.by, "by", os.Getenv("USER"), "approver recorded in the lockfile")
	cmd.Flags().BoolVar(&opts.all, "all", false, "approve every tool that is new or changed")
	cmd.Flags().BoolVar(&opts.prune, "prune", false, "drop lockfile entries for tools no longer in the catalog")
	return cmd
}

func approve(w io.Writer, r pin.Report, opts approveOptions) error {
	lock, err := pin.Read(opts.file)
	if err != nil {
		return err
	}
	selected, err := selectTools(r, opts)
	if err != nil {
		return err
	}
	approved := 0
	for i := range selected {
		t := &selected[i]
		if lock.Status(t.Tool()) == pin.StatusApproved {
			continue
		}
		if err := printChange(w, t, lock); err != nil {
			return err
		}
		lock = lock.Approve(t.Tool(), opts.by, opts.now())
		approved++
	}
	pruned := 0
	if opts.prune {
		pruned = pruneMissing(lock, r)
	}
	if approved == 0 && pruned == 0 {
		return printf(w, "nothing to approve\n")
	}
	if err := pin.Write(opts.file, lock); err != nil {
		return err
	}
	return printf(w, "approved %d, pruned %d, wrote %s\n", approved, pruned, opts.file)
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

func printChange(w io.Writer, t *pin.ToolReport, lock pin.Lockfile) error {
	status := lock.Status(t.Tool())
	if err := printf(w, "%s %s (upstream %s)\n", status, t.Name, t.Upstream); err != nil {
		return err
	}
	if status == pin.StatusChanged {
		prev := lock.Tools[t.Name]
		if err := printf(w, "  pin %s -> %s\n", shortPin(prev.Pin), shortPin(t.Pin)); err != nil {
			return err
		}
		if prev.Description != t.Description {
			return printDiff(w, prev.Description, t.Description)
		}
		return printf(w, "  description unchanged; schema or annotations changed\n")
	}
	for line := range strings.SplitSeq(t.Description, "\n") {
		if err := printf(w, "  + %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

func printDiff(w io.Writer, before, after string) error {
	old := strings.Split(before, "\n")
	cur := strings.Split(after, "\n")
	for _, line := range old {
		if !slices.Contains(cur, line) {
			if err := printf(w, "  - %s\n", line); err != nil {
				return err
			}
		}
	}
	for _, line := range cur {
		if !slices.Contains(old, line) {
			if err := printf(w, "  + %s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}
