package request

import (
	reqContext "context"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	providerContext "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/comm"
	"github.com/pkg/errors"
)

type Option struct {
	ClientContext   providerContext.Channel
	Timeouts        map[fab.TimeoutType]time.Duration
	ParentContext   reqContext.Context
	Retry           retry.Opts
	Targets         []fab.Peer
	Nonce           []byte
	EndorseNotifier Notifier
}

type Notifier struct {
	N     chan struct{}
	Block bool
}

func (n *Notifier) Notify() {
	if n.Block {
		n.N <- struct{}{}
	} else {
		select {
		case n.N <- struct{}{}:
		default:
		}
	}
}

type OptionProvider func(providerContext.Client, *Option) error

func WithTargets(targets ...fab.Peer) OptionProvider {
	return func(ctx providerContext.Client, o *Option) error {
		for _, t := range targets {
			if t == nil {
				return errors.New("target is nil")
			}
		}
		o.Targets = targets
		return nil
	}
}

func WithTargetEndpoints(keys ...string) OptionProvider {
	return func(ctx providerContext.Client, o *Option) error {
		var targets []fab.Peer
		for _, url := range keys {
			peerCfg, err := comm.NetworkPeerConfig(ctx.EndpointConfig(), url)
			if err != nil {
				return err
			}

			peer, err := ctx.InfraProvider().CreatePeerFromConfig(peerCfg)
			if err != nil {
				return errors.WithMessage(err, "creating peer from config failed")
			}
			targets = append(targets, peer)
		}
		return WithTargets(targets...)(ctx, o)
	}
}

func WithTimeout(timeoutType fab.TimeoutType, duration time.Duration) OptionProvider {
	return func(ctx providerContext.Client, o *Option) error {
		if o.Timeouts == nil {
			o.Timeouts = make(map[fab.TimeoutType]time.Duration)
		}
		o.Timeouts[timeoutType] = duration
		return nil
	}
}

func WithEndorseNotifier(notifier Notifier) OptionProvider {
	return func(ctx providerContext.Client, o *Option) error {
		o.EndorseNotifier = notifier
		return nil
	}
}

func WithNonceProvider(nonce []byte) OptionProvider {
	return func(ctx providerContext.Client, o *Option) error {
		o.Nonce = nonce
		return nil
	}
}
