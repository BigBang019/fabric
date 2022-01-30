package request

import (
	reqContext "context"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/context"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel/invoke"
	selectopts "github.com/hyperledger/fabric-sdk-go/pkg/client/common/selection/options"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/status"
	providerContext "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	providersFab "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/pkg/errors"
)

func Execute(provider providerContext.ChannelProvider, request channel.Request, optionProvider ...OptionProvider) (channel.Response, error) {
	ctx, err := provider()
	if err != nil {
		return channel.Response{}, err
	}

	opts := Option{}
	for _, option := range optionProvider {
		err = option(ctx, &opts)
		if err != nil {
			return channel.Response{}, err
		}
	}
	opts.ClientContext = ctx

	reqCtx, cancel := createReqContex(&opts)
	defer cancel()

	fmt.Println(reqCtx, cancel)

	requestContext, clientContext, err := prepareHandlerContexts(reqCtx, request, opts)
	if err != nil {
		return channel.Response{}, err
	}

	invokers := []Invoker{
		NewInvoker(invoke.NewEndorsementHandlerWithOpts(nil, WithNonce(opts.Nonce)), opts.EndorseNotifier),
		NewInvoker(invoke.NewEndorsementValidationHandler(nil)),
		NewInvoker(invoke.NewSignatureValidationHandler(nil)),
		NewInvoker(invoke.NewCommitHandler(nil)),
	}
	complete := make(chan bool, 1)
	go func() {
		for _, invoker := range invokers {
			invoker(requestContext, clientContext)
		}
		complete <- true
	}()

	select {
	case <-complete:
		return channel.Response(requestContext.Response), requestContext.Error
	case <-reqCtx.Done():
		return channel.Response{}, status.New(status.ClientStatus, status.Timeout.ToInt32(),
			"request timed out or been cancelled", nil)
	}
}

type Invoker func(*invoke.RequestContext, *invoke.ClientContext)

func NewInvoker(handler invoke.Handler, notifiers ...Notifier) Invoker {
	return func(requestContext *invoke.RequestContext, clientContext *invoke.ClientContext) {
		handler.Handle(requestContext, clientContext)
		for _, notifier := range notifiers {
			notifier.Notify()
		}
		fmt.Println("I'm Done.")
	}
}

func createReqContex(opts *Option) (reqContext.Context, reqContext.CancelFunc) {
	if opts.Timeouts == nil {
		opts.Timeouts = make(map[providersFab.TimeoutType]time.Duration)
	}
	if opts.Timeouts[providersFab.Execute] == 0 {
		opts.Timeouts[providersFab.Execute] = opts.ClientContext.EndpointConfig().Timeout(providersFab.Execute)
	}

	reqCtx, cancel := context.NewRequest(
		opts.ClientContext,
		context.WithTimeout(opts.Timeouts[providersFab.Execute]),
		context.WithParent(opts.ParentContext),
	)
	reqCtx = reqContext.WithValue(reqCtx, context.ReqContextTimeoutOverrides, opts.Timeouts[providersFab.Execute])
	return reqCtx, cancel
}

func prepareHandlerContexts(reqCtx reqContext.Context, request channel.Request, opts Option) (*invoke.RequestContext, *invoke.ClientContext, error) {
	if request.ChaincodeID == "" || request.Fcn == "" {
		return nil, nil, errors.New("ChaincodeID and Fcn are required")
	}
	transactor, err := opts.ClientContext.ChannelService().Transactor(reqCtx)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to create transactor")
	}

	selection, err := opts.ClientContext.ChannelService().Selection()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to create selection service")
	}

	discovery, err := opts.ClientContext.ChannelService().Discovery()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to create discovery service")
	}

	membership, err := opts.ClientContext.ChannelService().Membership()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "fail to create membership")
	}

	eventService, err := opts.ClientContext.ChannelService().EventService()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "event service creation failed")
	}

	peerFilter := func(peer providersFab.Peer) bool {
		return true
	}

	var peerSorter selectopts.PeerSorter
	// if o.TargetSorter != nil {
	// 	peerSorter = func(peers []fab.Peer) []fab.Peer {
	// 		return o.TargetSorter.Sort(peers)
	// 	}
	// }
	clientContext := &invoke.ClientContext{
		Selection:    selection,
		Discovery:    discovery,
		Membership:   membership,
		Transactor:   transactor,
		EventService: eventService,
	}

	reqOpts := &invoke.Opts{
		Retry:    opts.Retry,
		Targets:  opts.Targets,
		Timeouts: opts.Timeouts,
	}

	requestContext := &invoke.RequestContext{
		Request:         invoke.Request(request),
		Opts:            *reqOpts,
		Response:        invoke.Response{},
		RetryHandler:    retry.New(opts.Retry),
		Ctx:             reqCtx,
		SelectionFilter: peerFilter,
		PeerSorter:      peerSorter,
	}
	return requestContext, clientContext, nil
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
