package attack

type Attack interface {
	Prepare(chaincodeBytes []byte) error
	GetInfo() *map[string]string
	LaunchAttack() error
}

type Attacker struct {
	PackageInfo map[string]string
}

func (a *Attacker) Prepare(chaincodeBytes []byte) error {
	a.PackageInfo["0"] = string(chaincodeBytes)
	return nil
}
func (a *Attacker) GetInfo() *map[string]string {
	return &a.PackageInfo
}

func (a *Attacker) LaunchAttack() error {
	return nil
}