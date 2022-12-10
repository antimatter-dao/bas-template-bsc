// Copyright 2017 The go-ethereum Authors
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

// faucet is an Ether faucet backed by a light client.
package main

//go:generate go-bindata -nometadata -o website.go faucet.html
//go:generate gofmt -w -s website.go

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethstats"
	"github.com/ethereum/go-ethereum/les"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gorilla/websocket"

	lru "github.com/hashicorp/golang-lru"
)

var (
	genesisFlag = flag.String("genesis", "", "Genesis json file to seed the chain with")
	apiPortFlag = flag.Int("apiport", 8080, "Listener port for the HTTP API connection")
	ethPortFlag = flag.Int("ethport", 30303, "Listener port for the devp2p connection")
	bootFlag    = flag.String("bootnodes", "", "Comma separated bootnode enode URLs to seed with")
	netFlag     = flag.Uint64("network", 0, "Network ID to use for the Ethereum protocol")
	statsFlag   = flag.String("ethstats", "", "Ethstats network monitoring auth string")
	rpcApiFlag  = flag.String("rpcapi", "", "RPC api")
	natFlag     = flag.String("nat", "any", "port mapping mechanism (any|none|upnp|pmp|extip:<IP>)")

	netnameFlag = flag.String("faucet.name", "", "Network name to assign to the faucet")
	payoutFlag  = flag.Int("faucet.amount", 1, "Number of Ethers to pay out per user request")
	minutesFlag = flag.Int("faucet.minutes", 1440, "Number of minutes to wait between funding rounds")
	tiersFlag   = flag.Int("faucet.tiers", 3, "Number of funding tiers to enable (x3 time, x2.5 funds)")

	accJSONFlag = flag.String("account.json", "", "Key json file to fund user requests with")
	accPassFlag = flag.String("account.pass", "", "Decryption password to access faucet funds")

	captchaToken  = flag.String("captcha.token", "", "Recaptcha site key to authenticate client side")
	captchaSecret = flag.String("captcha.secret", "", "Recaptcha secret key to authenticate server side")

	noauthFlag = flag.Bool("noauth", false, "Enables funding requests without authentication")
	logFlag    = flag.Int("loglevel", 3, "Log level to use for Ethereum and the faucet")

	bep2eContracts     = flag.String("bep2eContracts", "", "the list of bep2p contracts")
	bep2eSymbols       = flag.String("bep2eSymbols", "", "the symbol of bep2p tokens")
	bep2eAmounts       = flag.String("bep2eAmounts", "", "the amount of bep2p tokens")
	fixGasPrice        = flag.Int64("faucet.fixedprice", 0, "Will use fixed gas price if specified")
	twitterTokenFlag   = flag.String("twitter.token", "", "Bearer token to authenticate with the v2 Twitter API")
	twitterTokenV1Flag = flag.String("twitter.token.v1", "", "Bearer token to authenticate with the v1.1 Twitter API")

	goerliFlag  = flag.Bool("goerli", false, "Initializes the faucet with Görli network config")
	rinkebyFlag = flag.Bool("rinkeby", false, "Initializes the faucet with Rinkeby network config")
)

var (
	ether        = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	bep2eAbiJson = `[ { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "owner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "spender", "type": "address" }, { "indexed": false, "internalType": "uint256", "name": "value", "type": "uint256" } ], "name": "Approval", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "from", "type": "address" }, { "indexed": true, "internalType": "address", "name": "to", "type": "address" }, { "indexed": false, "internalType": "uint256", "name": "value", "type": "uint256" } ], "name": "Transfer", "type": "event" }, { "inputs": [], "name": "totalSupply", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "decimals", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "symbol", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getOwner", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "name": "balanceOf", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "recipient", "type": "address" }, { "internalType": "uint256", "name": "amount", "type": "uint256" } ], "name": "transfer", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "_owner", "type": "address" }, { "internalType": "address", "name": "spender", "type": "address" } ], "name": "allowance", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "spender", "type": "address" }, { "internalType": "uint256", "name": "amount", "type": "uint256" } ], "name": "approve", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "sender", "type": "address" }, { "internalType": "address", "name": "recipient", "type": "address" }, { "internalType": "uint256", "name": "amount", "type": "uint256" } ], "name": "transferFrom", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" } ]`
)

var (
	gitCommit = "" // Git SHA1 commit hash of the release (set via linker flags)
	gitDate   = "" // Git commit date YYYYMMDD of the release (set via linker flags)
)

const (
	subscribeTimeout = 30 * time.Second
)

func main() {
	// Parse the flags and set up the logger to print everything requested
	flag.Parse()
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(*logFlag), log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	// Construct the payout tiers
	amounts := make([]string, *tiersFlag)
	for i := 0; i < *tiersFlag; i++ {
		// Calculate the amount for the next tier and format it
		amount := float64(*payoutFlag) * math.Pow(2.5, float64(i))
		amounts[i] = fmt.Sprintf("%s Native Tokens", strconv.FormatFloat(amount, 'f', -1, 64))
		if amount == 1 {
			amounts[i] = strings.TrimSuffix(amounts[i], "s")
		}
	}
	bep2eNumAmounts := make([]string, 0)
	if bep2eAmounts != nil && len(*bep2eAmounts) > 0 {
		bep2eNumAmounts = strings.Split(*bep2eAmounts, ",")
	}

	symbols := make([]string, 0)
	if bep2eSymbols != nil && len(*bep2eSymbols) > 0 {
		symbols = strings.Split(*bep2eSymbols, ",")
	}

	contracts := make([]string, 0)
	if bep2eContracts != nil && len(*bep2eContracts) > 0 {
		contracts = strings.Split(*bep2eContracts, ",")
	}

	if len(bep2eNumAmounts) != len(symbols) || len(symbols) != len(contracts) {
		log.Crit("Length of bep2eContracts, bep2eSymbols, bep2eAmounts mismatch")
	}

	bep2eInfos := make(map[string]bep2eInfo, len(symbols))
	for idx, s := range symbols {
		n, ok := big.NewInt(0).SetString(bep2eNumAmounts[idx], 10)
		if !ok {
			log.Crit("failed to parse bep2eAmounts")
		}
		amountStr := big.NewFloat(0).Quo(big.NewFloat(0).SetInt(n), big.NewFloat(0).SetInt64(params.Ether)).String()

		bep2eInfos[s] = bep2eInfo{
			Contract:  common.HexToAddress(contracts[idx]),
			Amount:    *n,
			AmountStr: amountStr,
		}
	}
	// Load up and render the faucet website
	tmpl, err := Asset("faucet.html")
	if err != nil {
		log.Crit("Failed to load the faucet template", "err", err)
	}
	website := new(bytes.Buffer)
	err = template.Must(template.New("").Parse(string(tmpl))).Execute(website, map[string]interface{}{
		"Network":    *netnameFlag,
		"Amounts":    amounts,
		"Recaptcha":  *captchaToken,
		"NoAuth":     *noauthFlag,
		"Bep2eInfos": bep2eInfos,
	})
	if err != nil {
		log.Crit("Failed to render the faucet template", "err", err)
	}
	// Load and parse the genesis block requested by the user
	genesis, err := getGenesis(genesisFlag, *goerliFlag, *rinkebyFlag)
	if err != nil {
		log.Crit("Failed to parse genesis config", "err", err)
	}
	// Convert the bootnodes to internal enode representations
	var enodes []*enode.Node
	for _, boot := range strings.Split(*bootFlag, ",") {
		if boot == "" {
			continue
		}
		if url, err := enode.Parse(enode.ValidSchemes, boot); err == nil {
			enodes = append(enodes, url)
		} else {
			log.Error("Failed to parse bootnode URL", "url", boot, "err", err)
		}
	}
	// Load up the account key and decrypt its password
	blob, err := ioutil.ReadFile(*accPassFlag)
	if err != nil {
		log.Crit("Failed to read account password contents", "file", *accPassFlag, "err", err)
	}
	pass := strings.TrimSuffix(string(blob), "\n")

	ks := keystore.NewKeyStore(filepath.Join(os.Getenv("HOME"), ".faucet", "keys"), keystore.StandardScryptN, keystore.StandardScryptP)
	if blob, err = ioutil.ReadFile(*accJSONFlag); err != nil {
		log.Crit("Failed to read account key contents", "file", *accJSONFlag, "err", err)
	}
	acc, err := ks.Import(blob, pass, pass)
	if err != nil && err != keystore.ErrAccountAlreadyExists {
		log.Crit("Failed to import faucet signer account", "err", err)
	}
	if err := ks.Unlock(acc, pass); err != nil {
		log.Crit("Failed to unlock faucet signer account", "err", err)
	}
	// Assemble and start the faucet light service
	var faucet *faucet
	if *rpcApiFlag != "" {
		faucet, err = newHttpFaucet(genesis, *rpcApiFlag, ks, website.Bytes(), bep2eInfos)
	} else {
		var natCfg nat.Interface
		natCfg, err = nat.Parse(*natFlag)
		if err != nil {
			utils.Fatalf("-nat: %v", err)
		}
		faucet, err = newFaucet(genesis, *ethPortFlag, enodes, *netFlag, natCfg, *statsFlag, ks, website.Bytes(), bep2eInfos)
	}
	if err != nil {
		log.Crit("Failed to start faucet", "err", err)
	}
	defer faucet.close()

	if err := faucet.listenAndServe(*apiPortFlag); err != nil {
		log.Crit("Failed to launch faucet API", "err", err)
	}
}

// request represents an accepted funding request.
type request struct {
	Id      string             `json:"-"`
	Avatar  string             `json:"avatar"`  // Avatar URL to make the UI nicer
	Account common.Address     `json:"account"` // Ethereum address being funded
	Time    time.Time          `json:"time"`    // Timestamp when the request was accepted
	Tx      *types.Transaction `json:"tx"`      // Transaction funding the account
}

type fundReq struct {
	Id       string
	Username string
	Avatar   string
	Symbol   string
	Tier     int64
	Address  common.Address
	Wsconn   *wsConn
}

type bep2eInfo struct {
	Contract  common.Address
	Amount    big.Int
	AmountStr string
}

type faucetState struct {
	// The current state of the faucet
	Header     *types.Header
	Reqs       []*request
	Balance    *big.Int
	Nonce      uint64
	Price      *big.Int
	PeerNumber int
}

type faucetStateBroadcast struct {
	source         chan *faucetState
	listeners      []chan *faucetState
	addListener    chan chan *faucetState
	removeListener chan (<-chan *faucetState)
}

func (s *faucetStateBroadcast) Broadcast(state *faucetState) {
	select {
	case s.source <- state:
	default:
	}
}

func (s *faucetStateBroadcast) Subscribe() <-chan *faucetState {
	newListener := make(chan *faucetState, 1)
	s.addListener <- newListener
	return newListener
}

func (s *faucetStateBroadcast) Unsubscription(channel <-chan *faucetState) {
	s.removeListener <- channel
}

func newFaucetStateBroadcast() *faucetStateBroadcast {
	service := &faucetStateBroadcast{
		source:         make(chan *faucetState, 1),
		listeners:      make([]chan *faucetState, 0),
		addListener:    make(chan chan *faucetState),
		removeListener: make(chan (<-chan *faucetState)),
	}
	go service.serve()
	return service
}

func (s *faucetStateBroadcast) serve() {
	defer func() {
		for _, listener := range s.listeners {
			if listener != nil {
				close(listener)
			}
		}
	}()

	for {
		select {
		case newListener := <-s.addListener:
			s.listeners = append(s.listeners, newListener)
		case listenerToRemove := <-s.removeListener:
			for i, ch := range s.listeners {
				if ch == listenerToRemove {
					s.listeners[i] = s.listeners[len(s.listeners)-1]
					s.listeners = s.listeners[:len(s.listeners)-1]
					close(ch)
					break
				}
			}
		case val, ok := <-s.source:
			if !ok {
				return
			}
			for _, listener := range s.listeners {
				if listener != nil {
					select {
					case listener <- val:
					default:
					}
				}
			}
		}
	}
}

// faucet represents a crypto faucet backed by an Ethereum light client.
type faucet struct {
	config *params.ChainConfig // Chain configurations for signing
	stack  *node.Node          // Ethereum protocol stack
	client *ethclient.Client   // Client connection to the Ethereum chain
	index  []byte              // Index page to serve up on the web

	keystore *keystore.KeyStore // Keystore containing the single signer
	account  accounts.Account   // Account funding user faucet requests
	head     *types.Header      // Current head header of the faucet
	balance  *big.Int           // Current balance of the faucet
	nonce    uint64             // Current pending nonce of the faucet
	price    *big.Int           // Current gas price to issue funds with

	timeouts  map[string]time.Time // History of users and their funding timeouts
	reqs      []*request           // Currently pending funding requests
	update    chan struct{}        // Channel to signal request updates
	fundQueue chan *fundReq        // Channel to signal funded requests

	faucetState *faucetStateBroadcast // Broadcast channel for faucet state

	lock sync.RWMutex // Lock protecting the faucet's internals

	bep2eInfos map[string]bep2eInfo
	bep2eAbi   abi.ABI

	fundedCache *lru.Cache // LRU cache of recently funded users
}

// wsConn wraps a websocket connection with a write mutex as the underlying
// websocket library does not synchronize access to the stream.
type wsConn struct {
	conn  *websocket.Conn
	wlock sync.Mutex
}

func newFaucet(genesis *core.Genesis, port int, enodes []*enode.Node, network uint64, natCfg nat.Interface, stats string, ks *keystore.KeyStore, index []byte, bep2eInfos map[string]bep2eInfo) (*faucet, error) {
	// Assemble the raw devp2p protocol stack
	stack, err := node.New(&node.Config{
		Name:    "geth",
		Version: params.VersionWithCommit(gitCommit, gitDate),
		DataDir: filepath.Join(os.Getenv("HOME"), ".faucet"),
		NoUSB:   true,
		P2P: p2p.Config{
			NAT:              natCfg,
			NoDiscovery:      true,
			DiscoveryV5:      true,
			ListenAddr:       fmt.Sprintf(":%d", port),
			MaxPeers:         25,
			BootstrapNodesV5: enodes,
		},
	})
	if err != nil {
		return nil, err
	}
	bep2eAbi, err := abi.JSON(strings.NewReader(bep2eAbiJson))
	if err != nil {
		return nil, err
	}
	// Assemble the Ethereum light client protocol
	cfg := ethconfig.Defaults
	cfg.SyncMode = downloader.LightSync
	cfg.NetworkId = network
	cfg.Genesis = genesis
	utils.SetDNSDiscoveryDefaults(&cfg, genesis.ToBlock(nil).Hash())

	lesBackend, err := les.New(stack, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to register the ethereum service: %s", err)
	}

	// Assemble the ethstats monitoring and reporting service'
	if stats != "" {
		if err := ethstats.New(stack, lesBackend.ApiBackend, lesBackend.Engine(), stats); err != nil {
			return nil, err
		}
	}
	// Boot up the client and ensure it connects to bootnodes
	if err := stack.Start(); err != nil {
		return nil, err
	}
	for _, boot := range enodes {
		old, err := enode.Parse(enode.ValidSchemes, boot.String())
		if err == nil {
			stack.Server().AddPeer(old)
		}
	}
	// Attach to the client and retrieve and interesting metadatas
	api, err := stack.Attach()
	if err != nil {
		stack.Close()
		return nil, err
	}
	client := ethclient.NewClient(api)

	lru, err := lru.New(20000)
	if err != nil {
		return nil, err
	}

	return &faucet{
		config:      genesis.Config,
		stack:       stack,
		client:      client,
		index:       index,
		keystore:    ks,
		account:     ks.Accounts()[0],
		timeouts:    make(map[string]time.Time),
		update:      make(chan struct{}, 1),
		fundQueue:   make(chan *fundReq, 1024),
		bep2eInfos:  bep2eInfos,
		bep2eAbi:    bep2eAbi,
		faucetState: newFaucetStateBroadcast(),
		fundedCache: lru,
	}, nil
}

func newHttpFaucet(genesis *core.Genesis, rpcApi string, ks *keystore.KeyStore, index []byte, bep2eInfos map[string]bep2eInfo) (*faucet, error) {
	bep2eAbi, err := abi.JSON(strings.NewReader(bep2eAbiJson))
	if err != nil {
		return nil, err
	}

	client, err := ethclient.Dial(rpcApi)
	if err != nil {
		return nil, err
	}

	lru, err := lru.New(20000)
	if err != nil {
		return nil, err
	}

	return &faucet{
		config:      genesis.Config,
		client:      client,
		index:       index,
		keystore:    ks,
		account:     ks.Accounts()[0],
		timeouts:    make(map[string]time.Time),
		update:      make(chan struct{}, 1),
		fundQueue:   make(chan *fundReq, 1024),
		bep2eInfos:  bep2eInfos,
		bep2eAbi:    bep2eAbi,
		faucetState: newFaucetStateBroadcast(),
		fundedCache: lru,
	}, nil
}

// close terminates the Ethereum connection and tears down the faucet.
func (f *faucet) close() error {
	if f.stack == nil {
		return nil
	}

	return f.stack.Close()
}

// listenAndServe registers the HTTP handlers for the faucet and boots it up
// for service user funding requests.
func (f *faucet) listenAndServe(port int) error {
	go f.loop()

	http.HandleFunc("/", f.webHandler)
	http.HandleFunc("/api", f.apiHandler)
	http.HandleFunc("/faucet-smart/api", f.apiHandler)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// webHandler handles all non-api requests, simply flattening and returning the
// faucet website.
func (f *faucet) webHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(f.index)
}

// apiHandler handles requests for Ether grants and transaction statuses.
func (f *faucet) apiHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	// Start tracking the connection and drop at the end
	defer conn.Close()
	wsconn := &wsConn{conn: conn}

	// Check source IP rate limit
	ip := ""
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}

	log.Info("New clinet request", "ip", ip)

	// register static broadcast
	faucetState := f.faucetState.Subscribe()
	defer f.faucetState.Unsubscription(faucetState)

	go func() {
		for {
			newState, ok := <-faucetState
			if !ok {
				return
			}

			if err := send(wsconn, map[string]interface{}{
				"funds":    new(big.Int).Div(newState.Balance, ether),
				"funded":   newState.Nonce,
				"peers":    newState.PeerNumber,
				"requests": newState.Reqs,
			}, time.Second); err != nil {
				log.Warn("Failed to send stats to client", "ip", ip, "err", err)
				wsconn.conn.Close()
				return
			}

			if err := send(wsconn, newState.Header, time.Second); err != nil {
				log.Warn("Failed to send header to client", "ip", ip, "err", err)
				wsconn.conn.Close()
				return
			}
		}
	}()

	sendCount := 0
	requestTimestamp := time.Now().Add(time.Duration(-100) * time.Millisecond)

	// Keep reading requests from the websocket until the connection breaks
	for {
		// Fetch the next funding request and validate against github
		var msg struct {
			URL     string `json:"url"`
			Tier    uint   `json:"tier"`
			Captcha string `json:"captcha"`
			Symbol  string `json:"symbol"`
		}
		if err = conn.ReadJSON(&msg); err != nil {
			return
		}

		// if send count > 100, return and close connection
		if sendCount > 100 {
			if err = sendError(wsconn, errors.New("too many requests from client")); err != nil {
				log.Warn("Failed to send busy error to client", "err", err)
			}

			return
		}
		sendCount++

		// if request timestamp < 100ms, return and close connection
		if time.Since(requestTimestamp) < time.Duration(100)*time.Millisecond {
			if err = sendError(wsconn, errors.New("too many requests from client")); err != nil {
				log.Warn("Failed to send busy error to client", "err", err)
			}

			return
		}

		if !*noauthFlag && !strings.HasPrefix(msg.URL, "https://twitter.com/") && !strings.HasPrefix(msg.URL, "https://www.facebook.com/") {
			if err = sendError(wsconn, errors.New("URL doesn't link to supported services")); err != nil {
				log.Warn("Failed to send URL error to client", "err", err)
				return
			}
			continue
		}
		if msg.Tier >= uint(*tiersFlag) {
			//lint:ignore ST1005 This error is to be displayed in the browser
			if err = sendError(wsconn, errors.New("Invalid funding tier requested")); err != nil {
				log.Warn("Failed to send tier error to client", "err", err)
				return
			}
			continue
		}
		log.Info("Faucet funds requested", "url", msg.URL, "tier", msg.Tier)

		// If captcha verifications are enabled, make sure we're not dealing with a robot
		if *captchaToken != "" {
			form := url.Values{}
			form.Add("secret", *captchaSecret)
			form.Add("response", msg.Captcha)

			res, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", form)
			if err != nil {
				if err = sendError(wsconn, err); err != nil {
					log.Warn("Failed to send captcha post error to client", "err", err)
					return
				}
				continue
			}
			var result struct {
				Success bool            `json:"success"`
				Errors  json.RawMessage `json:"error-codes"`
			}
			err = json.NewDecoder(res.Body).Decode(&result)
			res.Body.Close()
			if err != nil {
				if err = sendError(wsconn, err); err != nil {
					log.Warn("Failed to send captcha decode error to client", "err", err)
					return
				}
				continue
			}
			if !result.Success {
				log.Warn("Captcha verification failed", "err", string(result.Errors))
				//lint:ignore ST1005 it's funny and the robot won't mind
				if err = sendError(wsconn, errors.New("Beep-bop, you're a robot!")); err != nil {
					log.Warn("Failed to send captcha failure to client", "err", err)
					return
				}
				continue
			}
		}

		// Retrieve the Ethereum address to fund, the requesting user and a profile picture
		var (
			id       string
			username string
			avatar   string
			address  common.Address
		)
		switch {
		case strings.HasPrefix(msg.URL, "https://twitter.com/"):
			id, username, avatar, address, err = authTwitter(msg.URL, *twitterTokenV1Flag, *twitterTokenFlag)
		case strings.HasPrefix(msg.URL, "https://www.facebook.com/"):
			username, avatar, address, err = authFacebook(msg.URL)
			id = username
		case *noauthFlag:
			username, avatar, address, err = authNoAuth(msg.URL)
			id = username
		default:
			//lint:ignore ST1005 This error is to be displayed in the browser
			err = errors.New("Something funky happened, please open an issue at https://github.com/ethereum/go-ethereum/issues")
		}
		if err != nil {
			if err = sendError(wsconn, err); err != nil {
				log.Warn("Failed to send prefix error to client", "err", err)
				return
			}
			continue
		}
		log.Info("Faucet request valid", "url", msg.URL, "tier", msg.Tier, "user", username, "address", address)

		// Ensure the user didn't request funds too recently
		f.lock.Lock()

		// check if the user has already requested funds
		if qosT, exist := f.fundedCache.Get(address); exist {
			if time.Now().After(qosT.(time.Time)) {
				f.fundedCache.Remove(address)
			} else {
				f.fundedCache.Add(address, time.Now().Add(time.Duration(*minutesFlag)*time.Minute))
				f.lock.Unlock()

				if err = sendError(wsconn, errors.New("you have already requested funds recently, please try again later")); err != nil {
					log.Warn("Failed to send request error to client", "err", err)
					return
				}
				continue
			}
		}

		f.lock.Unlock()

		req := &fundReq{
			Id:       id,
			Username: username,
			Avatar:   avatar,
			Symbol:   msg.Symbol,
			Tier:     int64(msg.Tier),
			Address:  address,
			Wsconn:   wsconn,
		}

		select {
		case f.fundQueue <- req:
			requestTimestamp = time.Now()

			if err := sendSuccess(wsconn, "Funding request sent into queue, please waiting"); err != nil {
				log.Warn("Failed to send funding success to client", "err", err)
				return
			}
		default:
			if err = sendError(wsconn, errors.New("faucet is busy, please try again later")); err != nil {
				log.Warn("Failed to send busy error to client", "err", err)
				return
			}
		}
	}
}

// refresh attempts to retrieve the latest header from the chain and extract the
// associated faucet balance and nonce for connectivity caching.
func (f *faucet) refresh(head *types.Header) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Ensure a state update does not run for too long
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// If no header was specified, use the current chain head
	var err error
	if head == nil {
		if head, err = f.client.HeaderByNumber(ctx, nil); err != nil {
			return err
		}
	}
	// Retrieve the balance, nonce and gas price from the current head
	var (
		balance *big.Int
		nonce   uint64
		price   *big.Int
	)
	if balance, err = f.client.BalanceAt(ctx, f.account.Address, head.Number); err != nil {
		return err
	}
	if nonce, err = f.client.NonceAt(ctx, f.account.Address, head.Number); err != nil {
		return err
	}
	if fixGasPrice != nil && *fixGasPrice > 0 {
		price = big.NewInt(*fixGasPrice)
	} else {
		if price, err = f.client.SuggestGasPrice(ctx); err != nil {
			return err
		}
	}
	// Everything succeeded, update the cached stats and eject old requests
	f.head, f.balance = head, balance
	f.price, f.nonce = price, nonce

	for len(f.reqs) > 0 {
		if f.reqs[0].Tx.Nonce() < f.nonce {
			log.Info("Funding request consumed", "id", f.reqs[0].Id, "id", f.reqs[0].Id, "address", f.reqs[0].Account)

			f.reqs = f.reqs[1:]
		} else if time.Now().After(f.reqs[0].Time.Add(time.Minute)) {
			log.Error("Funding request timed out", "id", f.reqs[0].Id, "id", f.reqs[0].Id, "address", f.reqs[0].Account)

			f.reqs = f.reqs[1:]
		}

		break
	}

	timestamp := time.Unix(int64(head.Time), 0)
	log.Info(
		"Updated faucet state",
		"number", head.Number,
		"hash", head.Hash(),
		"age", common.PrettyAge(timestamp),
		"balance", balance,
		"nonce", nonce,
		"price", price,
	)

	return nil
}

func (f *faucet) fundHandle() {
	f.lock.Lock()
	defer f.lock.Unlock()

	defer func() {
		select {
		case f.update <- struct{}{}:
		default:
		}
	}()

	for {
		var req *fundReq
		ok := false

		select {
		case req, ok = <-f.fundQueue:
			if !ok {
				return
			}
		default:
			return
		}

		id := req.Id
		username := req.Username
		avatar := req.Avatar
		address := req.Address
		symbol := req.Symbol
		wsconn := req.Wsconn
		tier := req.Tier

		var (
			fund    bool
			timeout time.Time
		)
		if timeout = f.timeouts[id]; time.Now().After(timeout) {
			f.fundedCache.Add(address, time.Now().Add(time.Duration(*minutesFlag)*time.Minute))

			var tx *types.Transaction
			if symbol == "NativeToken" {
				// User wasn't funded recently, create the funding transaction
				amount := new(big.Int).Mul(big.NewInt(int64(*payoutFlag)), ether)
				amount = new(big.Int).Mul(amount, new(big.Int).Exp(big.NewInt(5), big.NewInt(tier), nil))
				amount = new(big.Int).Div(amount, new(big.Int).Exp(big.NewInt(2), big.NewInt(tier), nil))

				tx = types.NewTransaction(f.nonce+uint64(len(f.reqs)), address, amount, 21000, f.price, nil)
			} else {
				tokenInfo, ok := f.bep2eInfos[symbol]
				if !ok {
					log.Warn("Failed to find symbol", "symbol", symbol)
					continue
				}
				input, err := f.bep2eAbi.Pack("transfer", address, &tokenInfo.Amount)
				if err != nil {
					log.Warn("Failed to pack transfer transaction", "err", err)
					continue
				}
				tx = types.NewTransaction(f.nonce+uint64(len(f.reqs)), tokenInfo.Contract, nil, 420000, f.price, input)
			}
			signed, err := f.keystore.SignTx(f.account, tx, f.config.ChainID)
			if err != nil {
				if err = sendError(wsconn, err); err != nil {
					log.Warn("Failed to send transaction creation error to client", "err", err)
				}
				continue
			}
			// Submit the transaction and mark as funded if successful
			if err := f.client.SendTransaction(context.Background(), signed); err != nil {
				if err = sendError(wsconn, err); err != nil {
					log.Warn("Failed to send transaction transmission error to client", "err", err)
				}
				continue
			}
			f.reqs = append(f.reqs, &request{
				Id:      id,
				Avatar:  avatar,
				Account: address,
				Time:    time.Now(),
				Tx:      signed,
			})
			timeout := time.Duration(*minutesFlag*int(math.Pow(3, float64(tier)))) * time.Minute
			grace := timeout / 288 // 24h timeout => 5m grace

			f.timeouts[id] = time.Now().Add(timeout - grace)
			f.fundedCache.Add(address, f.timeouts[id])
			fund = true
		}

		// Send an error if too frequent funding, othewise a success
		if !fund {
			if err := sendError(wsconn, fmt.Errorf("%s left until next allowance", common.PrettyDuration(time.Until(timeout)))); err != nil { // nolint: gosimple
				log.Warn("Failed to send funding error to client", "err", err)
			}
			continue
		}

		if err := sendSuccess(wsconn, fmt.Sprintf("Funding request accepted for %s into %s", username, address.Hex())); err != nil {
			log.Warn("Failed to send funding success to client", "err", err)
			return
		}
	}
}

// loop keeps waiting for interesting events and pushes them out to connected
// websockets.
func (f *faucet) loop() {
	// Wait for chain events and push them to clients
	heads := make(chan *types.Header, 16)

	subscribeHead := func() ethereum.Subscription {
		sub, err := f.client.SubscribeNewHead(context.Background(), heads)
		if err != nil {
			log.Crit("Failed to subscribe to head events", "err", err)
			return nil
		}
		return sub
	}

	sub := subscribeHead()
	defer func() {
		if sub != nil {
			sub.Unsubscribe()
		}
	}()

	// Start a goroutine to update the state from head notifications in the background
	update := make(chan *types.Header)

	go func() {
		for head := range update {
			// New chain head arrived, query the current stats and stream to clients
			timestamp := time.Unix(int64(head.Time), 0)
			if time.Since(timestamp) > time.Hour {
				log.Warn("Skipping faucet refresh, head too old", "number", head.Number, "hash", head.Hash(), "age", common.PrettyAge(timestamp))
				continue
			}
			if err := f.refresh(head); err != nil {
				log.Warn("Failed to update faucet state", "block", head.Number, "hash", head.Hash(), "err", err)
				continue
			}

			f.fundHandle()

			f.lock.RLock()

			peerCount := -1
			if f.stack != nil {
				peerCount = f.stack.Server().PeerCount()
			}

			newState := &faucetState{
				Header:     head,
				Reqs:       append([]*request{}, f.reqs...),
				Balance:    f.balance,
				Nonce:      f.nonce,
				Price:      f.price,
				PeerNumber: peerCount,
			}

			f.lock.RUnlock()

			go func() {
				f.faucetState.Broadcast(newState)
			}()
		}
	}()

	// Wait for various events and assing to the appropriate background threads
	subscribeTimeoutTimer := time.NewTimer(subscribeTimeout)

	for {
		select {
		case head := <-heads:
			if !subscribeTimeoutTimer.Stop() {
				<-subscribeTimeoutTimer.C
			}
			subscribeTimeoutTimer.Reset(subscribeTimeout)

			// New head arrived, send if for state update if there's none running
			select {
			case update <- head:
			default:
			}
		case <-subscribeTimeoutTimer.C:
			subscribeTimeoutTimer.Reset(subscribeTimeout)

			// Subscription timeout, try to resubscribe
			if sub != nil {
				sub.Unsubscribe()
			}

			sub = subscribeHead()
		}
	}
}

// sends transmits a data packet to the remote end of the websocket, but also
// setting a write deadline to prevent waiting forever on the node.
func send(conn *wsConn, value interface{}, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	conn.wlock.Lock()
	defer conn.wlock.Unlock()
	conn.conn.SetWriteDeadline(time.Now().Add(timeout))
	return conn.conn.WriteJSON(value)
}

// sendError transmits an error to the remote end of the websocket, also setting
// the write deadline to 1 second to prevent waiting forever.
func sendError(conn *wsConn, err error) error {
	return send(conn, map[string]string{"error": err.Error()}, time.Second)
}

// sendSuccess transmits a success message to the remote end of the websocket, also
// setting the write deadline to 1 second to prevent waiting forever.
func sendSuccess(conn *wsConn, msg string) error {
	return send(conn, map[string]string{"success": msg}, time.Second)
}

// authTwitter tries to authenticate a faucet request using Twitter posts, returning
// the uniqueness identifier (user id/username), username, avatar URL and Ethereum address to fund on success.
func authTwitter(url string, tokenV1, tokenV2 string) (string, string, string, common.Address, error) {
	// Ensure the user specified a meaningful URL, no fancy nonsense
	parts := strings.Split(url, "/")
	if len(parts) < 4 || parts[len(parts)-2] != "status" {
		return "", "", "", common.Address{}, errors.New("invalid twitter status url")
	}
	// Strip any query parameters from the tweet id and ensure it's numeric
	tweetID := strings.Split(parts[len(parts)-1], "?")[0]
	if !regexp.MustCompile("^[0-9]+$").MatchString(tweetID) {
		return "", "", "", common.Address{}, errors.New("invalid tweet url")
	}
	// Twitter's API isn't really friendly with direct links.
	// It is restricted to 300 queries / 15 minute with an app api key.
	// Anything more will require read only authorization from the users and that we want to avoid.

	// If Twitter bearer token is provided, use the API, selecting the version
	// the user would prefer (currently there's a limit of 1 v2 app / developer
	// but unlimited v1.1 apps).
	switch {
	case tokenV1 != "":
		return authTwitterWithTokenV1(tweetID, tokenV1)
	case tokenV2 != "":
		return authTwitterWithTokenV2(tweetID, tokenV2)
	}
	// Twiter API token isn't provided so we just load the public posts
	// and scrape it for the Ethereum address and profile URL. We need to load
	// the mobile page though since the main page loads tweet contents via JS.
	url = strings.Replace(url, "https://twitter.com/", "https://mobile.twitter.com/", 1)

	res, err := http.Get(url)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	defer res.Body.Close()

	// Resolve the username from the final redirect, no intermediate junk
	parts = strings.Split(res.Request.URL.String(), "/")
	if len(parts) < 4 || parts[len(parts)-2] != "status" {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", "", common.Address{}, errors.New("Invalid Twitter status URL")
	}
	username := parts[len(parts)-3]

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	address := common.HexToAddress(string(regexp.MustCompile("0x[0-9a-fA-F]{40}").Find(body)))
	if address == (common.Address{}) {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", "", common.Address{}, errors.New("No BAS address found to fund")
	}
	var avatar string
	if parts = regexp.MustCompile("src=\"([^\"]+twimg.com/profile_images[^\"]+)\"").FindStringSubmatch(string(body)); len(parts) == 2 {
		avatar = parts[1]
	}
	return username + "@twitter", username, avatar, address, nil
}

// authTwitterWithTokenV1 tries to authenticate a faucet request using Twitter's v1
// API, returning the user id, username, avatar URL and Ethereum address to fund on
// success.
func authTwitterWithTokenV1(tweetID string, token string) (string, string, string, common.Address, error) {
	// Query the tweet details from Twitter
	url := fmt.Sprintf("https://api.twitter.com/1.1/statuses/show.json?id=%s", tweetID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	defer res.Body.Close()

	var result struct {
		Text string `json:"text"`
		User struct {
			ID       string `json:"id_str"`
			Username string `json:"screen_name"`
			Avatar   string `json:"profile_image_url"`
		} `json:"user"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	address := common.HexToAddress(regexp.MustCompile("0x[0-9a-fA-F]{40}").FindString(result.Text))
	if address == (common.Address{}) {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", "", common.Address{}, errors.New("No Ethereum address found to fund")
	}
	return result.User.ID + "@twitter", result.User.Username, result.User.Avatar, address, nil
}

// authTwitterWithTokenV2 tries to authenticate a faucet request using Twitter's v2
// API, returning the user id, username, avatar URL and Ethereum address to fund on
// success.
func authTwitterWithTokenV2(tweetID string, token string) (string, string, string, common.Address, error) {
	// Query the tweet details from Twitter
	url := fmt.Sprintf("https://api.twitter.com/2/tweets/%s?expansions=author_id&user.fields=profile_image_url", tweetID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", common.Address{}, err
	}
	defer res.Body.Close()

	var result struct {
		Data struct {
			AuthorID string `json:"author_id"`
			Text     string `json:"text"`
		} `json:"data"`
		Includes struct {
			Users []struct {
				ID       string `json:"id"`
				Username string `json:"username"`
				Avatar   string `json:"profile_image_url"`
			} `json:"users"`
		} `json:"includes"`
	}

	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return "", "", "", common.Address{}, err
	}

	address := common.HexToAddress(regexp.MustCompile("0x[0-9a-fA-F]{40}").FindString(result.Data.Text))
	if address == (common.Address{}) {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", "", common.Address{}, errors.New("No Ethereum address found to fund")
	}
	return result.Data.AuthorID + "@twitter", result.Includes.Users[0].Username, result.Includes.Users[0].Avatar, address, nil
}

// authFacebook tries to authenticate a faucet request using Facebook posts,
// returning the username, avatar URL and Ethereum address to fund on success.
func authFacebook(url string) (string, string, common.Address, error) {
	// Ensure the user specified a meaningful URL, no fancy nonsense
	parts := strings.Split(strings.Split(url, "?")[0], "/")
	if parts[len(parts)-1] == "" {
		parts = parts[0 : len(parts)-1]
	}
	if len(parts) < 4 || parts[len(parts)-2] != "posts" {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", common.Address{}, errors.New("Invalid Facebook post URL")
	}
	username := parts[len(parts)-3]

	// Facebook's Graph API isn't really friendly with direct links. Still, we don't
	// want to do ask read permissions from users, so just load the public posts and
	// scrape it for the Ethereum address and profile URL.
	//
	// Facebook recently changed their desktop webpage to use AJAX for loading post
	// content, so switch over to the mobile site for now. Will probably end up having
	// to use the API eventually.
	crawl := strings.Replace(url, "www.facebook.com", "m.facebook.com", 1)

	res, err := http.Get(crawl)
	if err != nil {
		return "", "", common.Address{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", common.Address{}, err
	}
	address := common.HexToAddress(string(regexp.MustCompile("0x[0-9a-fA-F]{40}").Find(body)))
	if address == (common.Address{}) {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", common.Address{}, errors.New("No BAS address found to fund")
	}
	var avatar string
	if parts = regexp.MustCompile("src=\"([^\"]+fbcdn.net[^\"]+)\"").FindStringSubmatch(string(body)); len(parts) == 2 {
		avatar = parts[1]
	}
	return username + "@facebook", avatar, address, nil
}

// authNoAuth tries to interpret a faucet request as a plain Ethereum address,
// without actually performing any remote authentication. This mode is prone to
// Byzantine attack, so only ever use for truly private networks.
func authNoAuth(url string) (string, string, common.Address, error) {
	address := common.HexToAddress(regexp.MustCompile("0x[0-9a-fA-F]{40}").FindString(url))
	if address == (common.Address{}) {
		//lint:ignore ST1005 This error is to be displayed in the browser
		return "", "", common.Address{}, errors.New("No BAS address found to fund")
	}
	return address.Hex() + "@noauth", "", address, nil
}

// getGenesis returns a genesis based on input args
func getGenesis(genesisFlag *string, goerliFlag bool, rinkebyFlag bool) (*core.Genesis, error) {
	switch {
	case genesisFlag != nil:
		var genesis core.Genesis
		err := common.LoadJSON(*genesisFlag, &genesis)
		return &genesis, err
	default:
		return nil, fmt.Errorf("no genesis flag provided")
	}
}
