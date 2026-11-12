package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

const EnvPrefix = "TOLLKEEPER_"

var ErrMissingEnv = errors.New("environment variable not set")

func Load(path string, lookup func(string) (string, bool)) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw, lookup, os.Environ)
}

func Parse(raw []byte, lookup func(string) (string, bool), environ func() []string) (Config, error) {
	parsed, err := yaml.Parser().Unmarshal(raw)
	if err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}
	expanded, err := expandValue(parsed, lookup)
	if err != nil {
		return Config{}, err
	}
	tree, ok := expanded.(map[string]any)
	if !ok {
		return Config{}, fmt.Errorf("parse yaml: %w", ErrInvalid)
	}
	k := koanf.New(".")
	if err := k.Load(structs.Provider(Defaults(), "koanf"), nil); err != nil {
		return Config{}, fmt.Errorf("load defaults: %w", err)
	}
	if err := k.Load(confmap.Provider(tree, ""), nil); err != nil {
		return Config{}, fmt.Errorf("load yaml: %w", err)
	}
	envProvider := env.Provider(".", env.Opt{
		Prefix:        EnvPrefix,
		EnvironFunc:   environ,
		TransformFunc: envKey,
	})
	if err := k.Load(envProvider, nil); err != nil {
		return Config{}, fmt.Errorf("load env: %w", err)
	}
	var cfg Config
	uc := koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
			ErrorUnused:      true,
			WeaklyTypedInput: true,
			Result:           &cfg,
			TagName:          "koanf",
		},
	}
	if err := k.UnmarshalWithConf("", &cfg, uc); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	for i := range cfg.Upstreams {
		cfg.Upstreams[i] = defaultUpstream(cfg.Upstreams[i])
	}
	return cfg, nil
}

func envKey(k, v string) (key string, value any) {
	k = strings.TrimPrefix(k, EnvPrefix)
	k = strings.ToLower(strings.ReplaceAll(k, "__", "."))
	return k, v
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandString(in string, lookup func(string) (string, bool)) (string, error) {
	var errs []error
	out := envRef.ReplaceAllStringFunc(in, func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		v, ok := lookup(name)
		if !ok {
			errs = append(errs, fmt.Errorf("${%s}: %w", name, ErrMissingEnv))
			return m
		}
		return v
	})
	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}
	return out, nil
}

func expandValue(v any, lookup func(string) (string, bool)) (any, error) {
	switch x := v.(type) {
	case string:
		return expandString(x, lookup)
	case map[string]any:
		out := make(map[string]any, len(x))
		var errs []error
		for k, e := range x {
			ev, err := expandValue(e, lookup)
			errs = append(errs, err)
			out[k] = ev
		}
		return out, errors.Join(errs...)
	case []any:
		out := make([]any, len(x))
		var errs []error
		for i, e := range x {
			ev, err := expandValue(e, lookup)
			errs = append(errs, err)
			out[i] = ev
		}
		return out, errors.Join(errs...)
	default:
		return v, nil
	}
}
