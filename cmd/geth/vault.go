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
	"context"
	"fmt"
	"math"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/urfave/cli.v1"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

/*
vault auth process
                     ┌───────┐
                     │ start │
                     └───┬───┘
                         │
                  ┌──────▼──────┐
            ┌─────┤ Exist token ├───┐
         No │     └─────────────┘   │Yes
            │                       │
    ┌───────▼───────┐               │
    │ AppRole login │               │
    └───────┬───────┘     ┌─────────▼───────────┐
            │             │ Read token for file │
    ┌───────▼────────┐    └─────────┬───────────┘
    │    Get token   │              │
    └───────┬────────┘              │
            │                       │
            └───────────┬───────────┘
                        │
            ┌───────────▼───────────┐
            │ Use token read account│
            └───────────┬───────────┘
                        │
               ┌────────▼───────┐
               │ Unlock account │
               └────────┬───────┘
                        │
                        │
                 ┌──────▼──────┐
   ┌────────────►│ Renew token │
   │             └──────┬──────┘
   │                    │
   │        ┌───────────▼────────────┐
   │        │ Save new token to file │
   │        └───────────┬────────────┘
   │                    │
   │       ┌────────────▼─────────────┐
   └───────┤ Sleep half token ttl time│
           └──────────────────────────┘

*/

const (
	vaultSecretKeyStoreField = "keystore"
	vaultSecretPasswordField = "password"

	vaultTokenFile = ".vault_token"
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

func vaultSaveTokenToFile(dataDir string, token string) {
	tokenFile := path.Join(dataDir, vaultTokenFile)

	f, err := os.CreateTemp(dataDir, vaultTokenFile+".tmp.*")
	if err != nil {
		log.Error("unable to create Vault token temp file", "err", err)
	}
	defer f.Close()

	_, err = f.WriteString(token)
	if err != nil {
		log.Error("unable to write Vault token to temp file", "err", err)
		return
	}

	err = os.Rename(f.Name(), tokenFile)
	if err != nil {
		log.Error("unable to rename Vault token file", "err", err)
		return
	}

	err = os.Chmod(tokenFile, 0600)
	if err != nil {
		log.Error("unable to change Vault token file permissions", "err", err)
		return
	}
}

func loginVaultAppRole(
	client *vault.Client,
	appRoleID string,
	appSecretID string,
	loginTimeout time.Duration,
) (*vault.Secret, error) {
	secretID := &auth.SecretID{FromString: appSecretID}
	appRoleAuth, err := auth.NewAppRoleAuth(appRoleID, secretID)

	if err != nil {
		log.Error("unable to create AppRole auth", "err", err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		loginTimeout,
	)
	defer cancel()

	secret, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		log.Error("unable to login Vault with AppRole", "err", err)
		return nil, err
	}

	return secret, nil
}

func renewVaultToken(
	closeCh chan struct{},
	dataDir string,
	client *vault.Client,
	secret *vault.Secret,
	renewTTL time.Duration,
) {
	// get token lease duration
	isRenewable, err := secret.TokenIsRenewable()
	if err != nil {
		log.Error("unable to check if token is renewable", "err", err)
		return
	}

	if !isRenewable {
		log.Error("token is not renewable")
		return
	}

	renewT := math.Max(renewTTL.Seconds(), 1)

	newSecret, err := client.Auth().Token().RenewSelf(int(renewT))
	if err != nil {
		log.Error("unable to renew token", "err", err)
		return
	}

	vaultSaveTokenToFile(dataDir, newSecret.Auth.ClientToken)

	watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:    newSecret,
		Increment: int(renewT / 2),
	})

	if err != nil {
		utils.Fatalf("unable to create Vault lifetime watcher: %v", err)
	}

	// renew the token
	go func() {
		go watcher.Start()
		defer watcher.Stop()

		for {
			select {
			case <-closeCh:
				return
			case err := <-watcher.DoneCh():
				if err != nil {
					log.Error("Failed to renew token Re-attempting login", "err", err)
				}
			case renewal := <-watcher.RenewCh():
				log.Info("Successfully renewed", "renewed", renewal)
				// save the renewed token
				vaultSaveTokenToFile(dataDir, renewal.Secret.Auth.ClientToken)
			}
		}
	}()
}

// vaultUnlockAccount unlocks an account by token auth for vault.
func vaultUnlockAccount(ctx *cli.Context, stack *node.Node) {
	if ctx.String(utils.VaultAddressFlag.Name) == "" {
		return
	}

	// wait close sigle
	closeCh := make(chan struct{})

	go func() {
		defer close(closeCh)
		stack.Wait()
	}()

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

	// Set the namespace
	namespace := ctx.String(utils.VaultNamespaceFlag.Name)
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	// read secret id from file
	secret := func() *vault.Secret {
		token, err := os.ReadFile(path.Join(stack.Config().DataDir, vaultTokenFile))
		if err == nil {
			client.SetToken(string(token))
			secret, err := client.Auth().Token().LookupSelf()
			if err != nil {
				log.Error("unable to lookup Vault token", "err", err)
			} else {
				return secret
			}
		}

		// login vault
		secret, err := loginVaultAppRole(
			client,
			ctx.String(utils.VaultAppRoleIDFlag.Name),
			ctx.String(utils.VaultAppRoleSecretIDFlag.Name),
			ctx.Duration(utils.VaultTimeoutFlag.Name),
		)

		if err != nil || secret == nil {
			utils.Fatalf("unable to login Vault: %v", err)
		}

		// save token to file
		vaultSaveTokenToFile(stack.Config().DataDir, secret.Auth.ClientToken)

		return secret
	}()

	renewVaultToken(
		closeCh,
		stack.Config().DataDir,
		client,
		secret,
		ctx.Duration(utils.VaultRenewTTLFlag.Name),
	)

	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	for _, path := range unlockPaths {
		secret, err := client.Logical().Read(path)
		if err != nil {
			utils.Fatalf("unable to read Vault secret: %v", err)
		}

		// Import the key into the keystore
		keyJSON, err := getVaultSecretData(secret, vaultSecretKeyStoreField)
		if err != nil {
			utils.Fatalf("unable to get Vault secret field data: %v", err)
			continue
		}

		password, err := getVaultSecretData(secret, vaultSecretPasswordField)
		if err != nil {
			utils.Fatalf("unable to get Vault secret field data: %v", err)
			continue
		}

		key, err := keystore.DecryptKey([]byte(keyJSON), password)
		if err != nil {
			utils.Fatalf("unable to decrypt Vault secret: %v", err)
			continue
		}

		_, err = ks.Import([]byte(keyJSON), password, password)
		if err != nil {
			log.Warn("Failed to import Vault account", "err", err)
		}

		err = ks.Unlock(accounts.Account{
			Address: key.Address,
		}, strings.TrimSpace(password))
		if err != nil {
			log.Error("failed to unlock Vault keystore", "err", err)
			continue
		}

		log.Info("Unlock address", "address", fmt.Sprintf("0x%x", key.Address))
	}
}
