package systemcontract

import (
	_ "embed"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// BSC contracts
const (
	ValidatorContract          = "0x0000000000000000000000000000000000001000"
	SlashContract              = "0x0000000000000000000000000000000000001001"
	SystemRewardContract       = "0x0000000000000000000000000000000000001002"
	LightClientContract        = "0x0000000000000000000000000000000000001003"
	TokenHubContract           = "0x0000000000000000000000000000000000001004"
	RelayerIncentivizeContract = "0x0000000000000000000000000000000000001005"
	RelayerHubContract         = "0x0000000000000000000000000000000000001006"
	GovHubContract             = "0x0000000000000000000000000000000000001007"
	TokenManagerContract       = "0x0000000000000000000000000000000000001008"
	CrossChainContract         = "0x0000000000000000000000000000000000002000"
)

// BAS contacts
const (
	StakingPoolContract    = "0x0000000000000000000000000000000000007001"
	GovernanceContract     = "0x0000000000000000000000000000000000007002"
	ChainConfigContract    = "0x0000000000000000000000000000000000007003"
	RuntimeUpgradeContract = "0x0000000000000000000000000000000000007004"
	DeployerProxyContract  = "0x0000000000000000000000000000000000007005"
	VaultContract          = "0x0000000000000000000000000000000000007006"
)

// system contract addresses
var (
	ValidatorContractAddress      = common.HexToAddress(ValidatorContract)
	SlashContractAddress          = common.HexToAddress(SlashContract)
	SystemRewardContractAddress   = common.HexToAddress(SystemRewardContract)
	StakingPoolContractAddress    = common.HexToAddress(StakingPoolContract)
	GovernanceContractAddress     = common.HexToAddress(GovernanceContract)
	ChainConfigContractAddress    = common.HexToAddress(ChainConfigContract)
	RuntimeUpgradeContractAddress = common.HexToAddress(RuntimeUpgradeContract)
	DeployerProxyContractAddress  = common.HexToAddress(DeployerProxyContract)
	VaultContractAddress          = common.HexToAddress(VaultContract)
)

var systemContracts = map[common.Address]bool{
	ValidatorContractAddress:    true,
	SlashContractAddress:        true,
	SystemRewardContractAddress: true,
	// we don't have these smart contract for BAS, it's not strictly required to disable them since they're not deployed
	common.HexToAddress(LightClientContract):        false,
	common.HexToAddress(RelayerHubContract):         false,
	common.HexToAddress(GovHubContract):             false,
	common.HexToAddress(TokenHubContract):           false,
	common.HexToAddress(RelayerIncentivizeContract): false,
	common.HexToAddress(CrossChainContract):         false,
	common.HexToAddress(TokenManagerContract):       false,
	// BAS smart contracts
	StakingPoolContractAddress:    true,
	GovernanceContractAddress:     true,
	ChainConfigContractAddress:    true,
	RuntimeUpgradeContractAddress: true,
	DeployerProxyContractAddress:  true,
	VaultContractAddress:          true,
}

func IsSystemContract(address common.Address) bool {
	return systemContracts[address]
}

var EvmHookRuntimeUpgradeAddress = common.HexToAddress("0x0000000000000000000000000000000000007f01")
var EvmHookDeployerProxyAddress = common.HexToAddress("0x0000000000000000000000000000000000007f02")

// VaultContractTransferEventHash is the vault contract Transfer event hash
//
// 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
var VaultContractTransferEventHash = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
