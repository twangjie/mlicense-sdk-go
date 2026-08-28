package mlicense

type Config struct {
	ProductID    string
	PublicKeyPEM string
	LicensePath  string
	ExtraKeys    map[string]string
}
