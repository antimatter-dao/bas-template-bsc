// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/systemcontract"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	Engine() consensus.Engine

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMBlockContext creates a new context for use in the EVM.
func NewEVMBlockContext(header *types.Header, chain ChainContext, author *common.Address) vm.BlockContext {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}
	return vm.BlockContext{
		CanTransfer:       CanTransfer,
		Transfer:          Transfer,
		GetHash:           GetHashFn(header, chain),
		Coinbase:          beneficiary,
		BlockNumber:       new(big.Int).Set(header.Number),
		Time:              new(big.Int).SetUint64(header.Time),
		Difficulty:        new(big.Int).Set(header.Difficulty),
		GasLimit:          header.GasLimit,
		CanCreateContract: CanCreateContract,
	}
}

// NewEVMTxContext creates a new transaction context for a single transaction.
func NewEVMTxContext(msg Message) vm.TxContext {
	return vm.TxContext{
		Origin:   msg.From(),
		GasPrice: new(big.Int).Set(msg.GasPrice()),
	}
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	// Cache will initially contain [refHash.parent],
	// Then fill up with [refHash.p, refHash.pp, refHash.ppp, ...]
	var cache []common.Hash

	return func(n uint64) common.Hash {
		// If there's no hash cache yet, make one
		if len(cache) == 0 {
			cache = append(cache, ref.ParentHash)
		}
		if idx := ref.Number.Uint64() - n - 1; idx < uint64(len(cache)) {
			return cache[idx]
		}
		// No luck in the cache, but we can start iterating from the last element we already know
		lastKnownHash := cache[len(cache)-1]
		lastKnownNumber := ref.Number.Uint64() - uint64(len(cache))

		for {
			header := chain.GetHeader(lastKnownHash, lastKnownNumber)
			if header == nil {
				break
			}
			cache = append(cache, header.ParentHash)
			lastKnownHash = header.ParentHash
			lastKnownNumber = header.Number.Uint64() - 1
			if n == lastKnownNumber {
				return lastKnownHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}

// CanCreateContract returns whether caller can create contract or not
func CanCreateContract(db vm.StateDB, caller common.Address) bool {
	hash := calDeployerSlotHash(caller)
	storage := db.GetState(systemcontract.DeployerProxyContractAddress, hash)
	deployer := hashToDeployer(storage)

	return deployer.Exists && !deployer.Banned
}

type deployer struct {
	Exists  bool
	Address common.Address
	Banned  bool
}

func hashToDeployer(hash common.Hash) *deployer {
	v := hash.Bytes()

	return &deployer{
		Exists:  v[31] > 0,                       // the lowest byte
		Address: common.BytesToAddress(v[11:31]), // the address account
		Banned:  v[11] > 0,                       // the 21st lowest byte
	}
}

const (
	_contractDeployerSlot = 100
)

// calCallerSlotHash returns the storage hash of a deploer
//
// Genesis contract commit SHA: f1be5672e6a2b94bc8414eb598564456e047f75d.
//
//     uint8 private _initialized; // position 0
//     bool private _initializing; // position 0
//     IStaking internal immutable _STAKING_CONTRACT; // address position 0
//     ISlashingIndicator internal immutable _SLASHING_INDICATOR_CONTRACT; // position 1
//     ISystemReward internal immutable _SYSTEM_REWARD_CONTRACT; // position 2
//     IStakingPool internal immutable _STAKING_POOL_CONTRACT;
//     IGovernance internal immutable _GOVERNANCE_CONTRACT;
//     IChainConfig internal immutable _CHAIN_CONFIG_CONTRACT;
//     IRuntimeUpgrade internal immutable _RUNTIME_UPGRADE_CONTRACT;
//     IDeployerProxy internal immutable _DEPLOYER_PROXY_CONTRACT;
//     bytes internal _delayedInitializer; // position 8, save its byte length
//     uint256[_SKIP_OFFSET] private __removed; // position begins at 9, hold 10 slot
//     uint256[_LAYOUT_OFFSET - _SKIP_OFFSET - 2] private __reserved; // position begins at 19, hold 88 slot
//     mapping(address => Deployer) public _contractDeployers; // position 107
//
// The mapping position is 107, and the Deployer struct consumes only 1 words.
//     struct Deployer {
//         bool exists; // lower byte 0
//         address account; // lower byte 20 to 1
//         bool banned; // lower byte 21
//     }
//     mapping(address => Deployer) private _contractDeployers;
//
// Those constants are hardcoded, so the contract commit SHA must be specified.
func calDeployerSlotHash(caller common.Address) common.Hash {
	// NOTE: The deployer mapping must be public for storage reading.
	return common.BytesToHash(getAddressMapping(caller, _contractDeployerSlot))
}

// getAddressMapping returns the key for the SC storage mapping (address => something)
//
// More information:
// https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
func getAddressMapping(address common.Address, slot int64) []byte {
	bigSlot := big.NewInt(slot)
	finalSlice := append(
		common.PadLeftOrTrim(address.Bytes(), 32),
		common.PadLeftOrTrim(bigSlot.Bytes(), 32)...,
	)

	return crypto.Keccak256(finalSlice)
}
