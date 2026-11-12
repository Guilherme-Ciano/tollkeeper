package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

const EnvPrefix = "TOLLKEEPER_"

var (
	ErrMissingEnv   = errors.New("environment variable not set")
	ErrMultilineEnv = errors.New("environment variable contains a newline")
)

func Load(path string, lookup func(string) (string, bool)) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw, lookup, os.Environ)
}

func Parse(raw []byte, lookup func(string) (string, bool), environ func() []string) (Config, error) {
	expanded, err := ExpandEnv(raw, lookup)
	if err != nil {
		return Config{}, err
	}
	k := koanf.New(".")
	if err := k.Load(structs.Provider(Defaults(), "koanf"), nil); err != nil {
		return Config{}, fmt.Errorf("load defaults: %w", err)
	}
	if err := k.Load(rawbytes.Provider(expanded), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
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

func ExpandEnv(raw []byte, lookup func(string) (string, bool)) ([]byte, error) {
	var errs []error
	out := envRef.ReplaceAllFunc(raw, func(m []byte) []byte {
		name := string(envRef.FindSubmatch(m)[1])
		v, ok := lookup(name)
		if !ok {
			errs = append(errs, fmt.Errorf("${%s}: %w", name, ErrMissingEnv))
			return m
		}
		if strings.ContainsAny(v, "\r\n") {
			errs = append(errs, fmt.Errorf("${%s}: %w", name, ErrMultilineEnv))
			return m
		}
		return []byte(v)
	})
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}
