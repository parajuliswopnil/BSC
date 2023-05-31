package main

import (
	// "fmt"
	// "bytes"
	"context"
	// "errors"
	"fmt"

	// "sync"

	"bsc/bsc"
	"math/big"

	// "github.com/ethereum/go-ethereum/consensus/parlia"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	// "github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	// "github.com/ethereum/go-ethereum/consensus"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url := "https://data-seed-prebsc-1-s1.binance.org:8545"
	clrpc, err := rpc.Dial(url)
	if err != nil {
		return
	}

	ethcl := ethclient.NewClient(clrpc)

	chainid, err := ethcl.ChainID(ctx)
	// 29295050
	blockNumber := 29295000
	fmt.Println(blockNumber)

	validatorHeight := big.NewInt(int64(blockNumber + 200))
	
	// nextHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber + 1)))

	previousHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))

	previousHeaderToSuppliedHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber - 1)))

	previousToPrevHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(29649198)))

	validatorHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber - 200)))
	fmt.Println(len(previousHeader.Extra))

	verifier := bsc.NewVerifier(big.NewInt(int64(blockNumber)), chainid, validatorHeight, previousHeader.ParentHash, validatorHeader, ethcl, previousToPrevHeader)
	fmt.Println(verifier)

	// previousHeader, err = ethcl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))

	for i := blockNumber; i < blockNumber+1010; i++ {
		nextblockHeader, err := ethcl.HeaderByNumber(ctx, big.NewInt(int64(i+1)))

		err = verifier.Verify(previousHeaderToSuppliedHeader, previousHeader, nextblockHeader, nil)
		// if err != nil {
		// 	fmt.Println(err)
		// 	return 
		// }

		// err = verifier.VerifyVoteAttestation(previousHeader, verifier.ParentHeader)
		if err != nil {
			// if nextblockHeader.Number.Uint64() % 200 == 0 {
			// 	fmt.Println(err)
			// 	verifier.UpdateValidatorsMap(nextblockHeader)
			// 	i -= 1
			// 	continue
			// }
			fmt.Println(err)
			fmt.Println("The block number is: ", i)
			i--
			continue
		}

		err = verifier.Update(previousHeaderToSuppliedHeader, previousHeader)
		if err != nil {
			fmt.Println(err)
			return
		}
		previousHeaderToSuppliedHeader = previousHeader
		previousHeader = nextblockHeader

	}

	// headerExtra := previousHeader.Extra

	// num := int(headerExtra[32])

	// start := 32 + 1
	// end := start + num * 68

	// address, publicKey, err := parseValidators(previousHeader, headerExtra[start:end])

	// fmt.Println("Address is :", address)
	// fmt.Println("Public key is: ", publicKey)
}

const (
	validatorBytesLength = 68
)

// func parseValidators(header *types.Header, validatorsBytes []byte) ([]common.Address, []types.BLSPublicKey, error) {
// 	if len(validatorsBytes) == 0 {
// 		return nil, nil, errors.New("invalid validators bytes")
// 	}

// 	n := len(validatorsBytes) / validatorBytesLength
// 	fmt.Println("validators byte main ", n)
// 	cnsAddrs := make([]common.Address, n)
// 	voteAddrs := make([]types.BLSPublicKey, n)
// 	for i := 0; i < n; i++ {
// 		cnsAddrs[i] = common.BytesToAddress(validatorsBytes[i*validatorBytesLength : i*validatorBytesLength+common.AddressLength])
// 		copy(voteAddrs[i][:], validatorsBytes[i*validatorBytesLength+common.AddressLength:(i+1)*validatorBytesLength])
// 	}
// 	return cnsAddrs, voteAddrs, nil
// }

