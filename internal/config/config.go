package config

import "github.com/ilyakaznacheev/cleanenv"

type Config struct {
	ProxyIP          string   `env:"PROXY_IP"          env-required:"true"`
	ProxyPort        uint16   `env:"PROXY_PORT"        env-default:"8443"`
	NetworkInterface string   `env:"NETWORK_INTERFACE" env-default:"eth0"`
	CgroupPath       string   `env:"CGROUP_PATH"       env-default:"/sys/fs/cgroup"`
	AIDomains        []string `env:"AI_DOMAINS"        env-separator:","`
	LogLevel         string   `env:"LOG_LEVEL"         env-default:"info"`
}

func Load() (*Config, error) {
	var cfg Config

	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
