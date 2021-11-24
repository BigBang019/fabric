package attack

import (
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/protoutil"
)

type UnpackedProposal struct {
	Channel  string
	Contract string
	Function string
	Args     [][]byte
	Creator  []byte
}

func parse(signedProp *pb.SignedProposal) (*UnpackedProposal, error) {
	prop, err := protoutil.UnmarshalProposal(signedProp.ProposalBytes)
	if err != nil {
		return nil, err
	}
	hdr, err := protoutil.UnmarshalHeader(prop.Header)
	if err != nil {
		return nil, err
	}
	chdr, err := protoutil.UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		return nil, err
	}
	shdr, err := protoutil.UnmarshalSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return nil, err
	}
	cpp, err := protoutil.UnmarshalChaincodeProposalPayload(prop.Payload)
	if err != nil {
		return nil, err
	}
	cis, err := protoutil.UnmarshalChaincodeInvocationSpec(cpp.Input)
	if err != nil {
		return nil, err
	}
	return &UnpackedProposal{
		Channel:  chdr.ChannelId,
		Contract: cis.ChaincodeSpec.ChaincodeId.Name,
		Function: string(cis.ChaincodeSpec.Input.Args[0]),
		Args:     cis.ChaincodeSpec.Input.Args[1:],
		Creator:  shdr.Creator,
	}, nil
}
