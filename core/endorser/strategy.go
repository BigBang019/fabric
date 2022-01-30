package endorser

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

var strategyPath = filepath.Join(cfgPath, "strategy/strategy.yaml")

type Strategy struct {
	Chaincodes map[string]*Chaincode `yaml:"chaincode,omitempty"`
}

type Chaincode map[string]*Function

type Function struct {
	Function string   `yaml:"function"`
	Args     []string `yaml:"args"`
}

func LoadStrategy() (*Strategy, error) {
	raw, err := ioutil.ReadFile(strategyPath)
	if err != nil {
		return nil, err
	}
	var strategy Strategy
	err = yaml.Unmarshal(raw, &strategy)
	if err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (s *Strategy) Prepare(up *UnpackedProposal) (string, [][]byte, error) {
	ccn := up.ChaincodeName
	chaincode, ok := s.Chaincodes[ccn]
	if !ok {
		return "", nil, nil
	}

	fc, ok := (*chaincode)[string(up.Input.Args[0])]
	if !ok {
		return "", nil, nil
	}

	newfcn := fc.Function
	newargs := make([][]byte, len(fc.Args))
	ls := ""
	for id, arg := range fc.Args {
		if arg[0] == '$' {
			idx, err := strconv.Atoi(arg[1:])
			if err != nil {
				return "", nil, err
			}
			if idx >= len(up.Input.Args) {
				return "", nil, fmt.Errorf("arg length: %v, but accessing %v", len(up.Input.Args), idx)
			}
			newargs[id] = up.Input.Args[idx]
			ls += string(up.Input.Args[idx]) + ", "
		} else {
			newargs[id] = []byte(arg)
			ls += arg + ", "
		}
	}
	logger.Infof("newfcn: %v, newargs: %v", newfcn, ls)
	logger.Infof("args: %v", newargs)

	return newfcn, newargs, nil
}
