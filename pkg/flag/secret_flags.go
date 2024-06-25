package flag

var (
	SecretConfigFlag = Flag[string]{
		Name:       "secret-config",
		ConfigName: "secret.config",
		Default:    "trivy-secret.yaml",
		Usage:      "specify a path to config file for secret scanning",
	}
)

type SecretFlagGroup struct {
	SecretConfig *Flag[string]
}

func NewSecretFlagGroup() *SecretFlagGroup {
	return &SecretFlagGroup{
		SecretConfig: SecretConfigFlag.Clone(),
	}
}

func (f *SecretFlagGroup) Name() string {
	return "Secret"
}

func (f *SecretFlagGroup) Flags() []Flagger {
	return []Flagger{f.SecretConfig}
}
