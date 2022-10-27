// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"strings"

	"gopkg.in/urfave/cli.v1"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	vault "github.com/hashicorp/vault/api"
)

const (
	vaultSecretKeyStoreField = "keystore"
	vaultSecretPasswordField = "password"
)

var errUnableToReadVaultSecretData = fmt.Errorf("unable to read Vault secret data")

func getVaultSecretData(secret *vault.Secret, field string) (string, error) {
	if secret == nil {
		return "", fmt.Errorf("secret is nil")
	}

	if secret.Data == nil {
		return "", fmt.Errorf("secret data is nil")
	}

	if secret.Data["data"] == nil {
		return "", errUnableToReadVaultSecretData
	}

	data, err := secret.Data["data"].(map[string]interface{})
	if !err {
		return "", errUnableToReadVaultSecretData
	}

	if data[field] == nil {
		return "", fmt.Errorf("secret field %v is nil", field)
	}

	return data[field].(string), nil
}

// vaultUnlockAccount unlocks an account by token auth for vault.
func vaultUnlockAccount(ctx *cli.Context, stack *node.Node) {
	var unlockPaths []string
	inputs := strings.Split(ctx.String(utils.VaultUnlockedPathFlag.Name), ",")

	if len(inputs) == 0 {
		return
	}

	for _, input := range inputs {
		if trimmed := strings.TrimSpace(input); trimmed != "" {
			unlockPaths = append(unlockPaths, trimmed)
		}
	}

	config := vault.DefaultConfig()

	config.Address = ctx.String(utils.VaultAddressFlag.Name)

	client, err := vault.NewClient(config)
	if err != nil {
		utils.Fatalf("unable to initialize Vault client: %v", err)
	}

	vaultToken := ctx.String(utils.VaultAuthTokenFlag.Name)
	if vaultToken != "" {
		client.SetToken(vaultToken)
	}

	// Set the namespace
	namespace := ctx.String(utils.VaultNamespaceFlag.Name)
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	for _, path := range unlockPaths {
		secret, err := client.Logical().Read(path)
		if err != nil {
			utils.Fatalf("unable to read Vault secret: %v", err)
		}

		// Import the key into the keystore
		keyJSON, err := getVaultSecretData(secret, vaultSecretKeyStoreField)
		if err != nil {
			log.Warn("unable to get Vault secret field data", "err", err)
			continue
		}

		password, err := getVaultSecretData(secret, vaultSecretPasswordField)
		if err != nil {
			log.Warn("unable to get Vault secret field data", "err", err)
			continue
		}

		key, err := keystore.DecryptKey([]byte(keyJSON), password)
		if err != nil {
			log.Warn("unable to decrypt Vault secret", "err", err)
			continue
		}

		err = ks.Unlock(accounts.Account{
			Address: key.Address,
		}, strings.TrimSpace(password))
		if err != nil {
			log.Error("failed to unlock Vault key", "err", err)
		}

		log.Info("Unlock address", "address", fmt.Sprintf("0x%x", key.Address))
	}
}
