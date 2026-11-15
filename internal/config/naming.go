package config

import (
	"fmt"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
)

func (c *Config) Naming() catalog.Naming {
	n := catalog.Naming{Separator: c.Server.NamespaceSeparator, Bare: !c.Server.NamespaceTools}
	if n.Bare && len(c.Upstreams) == 1 {
		n.Upstream = c.Upstreams[0].ID
	}
	return n
}

func (c *Config) Warnings() []string {
	if c.Server.NamespaceTools || c.Server.NamespaceSeparator == "" {
		return nil
	}
	sep := c.Server.NamespaceSeparator
	var out []string
	check := func(field string, globs []string) {
		for j, g := range globs {
			if strings.Contains(g, sep) {
				out = append(out, fmt.Sprintf(
					"%s[%d]: %q contains the separator %q, but server.namespace_tools is false, so tool names "+
						"carry no upstream prefix and this glob only matches tools whose own name contains it",
					field, j, g, sep))
			}
		}
	}
	for i := range c.Policy.Rules {
		check(fmt.Sprintf("policy.rules[%d].tools", i), c.Policy.Rules[i].Tools)
	}
	for i := range c.RateLimits.Rules {
		check(fmt.Sprintf("rate_limits.rules[%d].tools", i), c.RateLimits.Rules[i].Tools)
	}
	return out
}
