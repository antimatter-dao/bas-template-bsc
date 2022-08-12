package core

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCalDeployerSlotHash(t *testing.T) {
	tests := []struct {
		caller common.Address
		result common.Hash
	}{
		{
			caller: common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"),
			result: common.HexToHash("0xb25c980813ebaf8df9bdd1ec576f1d2f7d17a7cdf38b0dd1a02ebb4ff3b08513"),
		},
		{
			caller: common.HexToAddress("0x8EA9594f23a7E9342721e19b3199FE8507AC1973"),
			result: common.HexToHash("0x739d5adf7e9a8d5a83e280bb3c6cf5aac9d9e0c1be78a6cf5e4603146a27ed23"),
		},
		{
			caller: common.HexToAddress("0x6067a1C57913Fd5aB883453fA86F50bF7Ce0A14C"),
			result: common.HexToHash("0x3abd1aaffc609327035a992e92fdfe94aca75dfb34ab452cb076b512dd910d60"),
		},
	}

	for _, tt := range tests {
		hash := calDeployerSlotHash(tt.caller)
		if tt.result != hash {
			t.Errorf("calDeployerSlotHash failed. expected: %s, got: %s", tt.result, hash)
		}
	}
}

func TestHashToDeployer(t *testing.T) {
	tests := []struct {
		hash   common.Hash
		result *deployer
	}{
		{
			hash: common.HexToHash("0x000000000000000000000000a601f45688dba8a070722073b015277cf3672501"),
			result: &deployer{
				Exists:  true,
				Address: common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"),
				Banned:  false,
			},
		},
		{
			hash: common.HexToHash("0x00000000000000000000008EA9594f23a7E9342721e19b3199FE8507AC197301"),
			result: &deployer{
				Exists:  true,
				Address: common.HexToAddress("8EA9594f23a7E9342721e19b3199FE8507AC1973"),
				Banned:  false,
			},
		},
		{
			hash: common.HexToHash("0x00000000000000000000016067a1C57913Fd5aB883453fA86F50bF7Ce0A14C01"),
			result: &deployer{
				Exists:  true,
				Address: common.HexToAddress("6067a1C57913Fd5aB883453fA86F50bF7Ce0A14C"),
				Banned:  true,
			},
		},
	}

	for _, tt := range tests {
		deployer := hashToDeployer(tt.hash)
		if !reflect.DeepEqual(tt.result, deployer) {
			t.Errorf("calDeployerSlotHash failed. expected: %+v, got: %+v", tt.result, deployer)
		}
	}
}
