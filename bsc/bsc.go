package bsc

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"sync"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	// ethTypes "github.com/ethereum/go-ethereum/core/types"

	// "github.com/icon-project/icon-bridge/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls"
	"github.com/willf/bitset"
)

const (
	extraVanity                     = 32          // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal                       = 65          // Fixed number of extra-data suffix bytes reserved for signer seal
	defaultEpochLength              = uint64(200) // Default number of blocks of checkpoint to update validatorSet from contract
	validatorBytesLengthBeforeLuban = ethCommon.AddressLength
	BLSPublicKeyLength              = 48

	validatorBytesLength              = 68
	validatorNumberSize               = 1                  // Fix number of bytes to indicate the number of validators in each epoch
	ParliaGasLimitBoundDivisor uint64 = 256                // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit                uint64 = 5000               // Minimum the gas limit may ever be.
	MaxGasLimit                uint64 = 0x7fffffffffffffff // Maximum the gas limit (2^63-1).
	attestationBytes                  = 180
)

var (
	lubanBlockTestnet                 = big.NewInt(29295050)
	big1      = big.NewInt(1)
	uncleHash = types.CalcUncleHash(nil)
)

var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	errMissingValidators = errors.New("epoch block does not have validators")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")
)

type VerifierOptions struct {
	BlockHeight   uint64   `json:"blockHeight"`
	BlockHash     HexBytes `json:"parentHash"`
	ValidatorData HexBytes `json:"validatorData"`
}

// next points to height whose parentHash is expected
// parentHash of height h is got from next-1's hash
type Verifier struct {
	chainID                    *big.Int
	mu                         sync.RWMutex
	next                       *big.Int
	parentHash                 ethCommon.Hash
	validators                 map[ethCommon.Address]bool
	prevValidators             map[ethCommon.Address]bool
	validatorPubKey            map[ethCommon.Address]types.BLSPublicKey
	prevValidatorPubKey        map[ethCommon.Address]types.BLSPublicKey
	useNewValidatorsFromHeight *big.Int
	ParentHeader               []*types.Header
}

type IVerifier interface {
	Next() *big.Int
	Verify(previousHeader, header *types.Header, nextHeader *types.Header, receipts types.Receipts) error
	Update(previousHeader, header *types.Header) (err error)
	ParentHash() ethCommon.Hash
	IsValidator(addr ethCommon.Address, curHeight *big.Int) bool
}

func NewVerifier(number, chainID, useNewValidatorsFromHeight *big.Int, parentHash ethCommon.Hash, validatorHeader *types.Header, ethClient *ethclient.Client, prevHeader *types.Header) *Verifier {
	validators, validatorPubKey, err := parseValidators(validatorHeader)
	fmt.Println(validators, validatorPubKey)

	if err != nil {
		return nil
	}
	parentHeaderList := make([]*types.Header, 1)
	parentHeaderList = append(parentHeaderList, prevHeader)
	valAddressMap := make(map[ethCommon.Address]bool)
	valPublicKey := make(map[ethCommon.Address]types.BLSPublicKey)
	for i := 0; i < len(validators); i++ {
		valAddressMap[validators[i]] = true
		if isLubanBlock(validatorHeader.Number) {
			valPublicKey[validators[i]] = validatorPubKey[i]
		}
	}

	return &Verifier{
		mu:                         sync.RWMutex{},
		next:                       number,
		parentHash:                 parentHash,
		chainID:                    chainID,
		useNewValidatorsFromHeight: useNewValidatorsFromHeight,
		prevValidators:             valAddressMap,
		validators:                 valAddressMap,
		prevValidatorPubKey:        valPublicKey,
		validatorPubKey:            valPublicKey,
		ParentHeader:               parentHeaderList,
	}
}

func (vr *Verifier) Next() *big.Int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return (&big.Int{}).Set(vr.next)
}

func (vr *Verifier) ChainID() *big.Int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return (&big.Int{}).Set(vr.chainID)
}

func (vr *Verifier) ParentHash() ethCommon.Hash {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return ethCommon.BytesToHash(vr.parentHash.Bytes())
}

func (vr *Verifier) IsValidator(addr ethCommon.Address, curHeight *big.Int) bool {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	exists := false
	if curHeight.Cmp(vr.useNewValidatorsFromHeight) >= 0 {
		_, exists = vr.validators[addr]
	} else {
		fmt.Println("should reach here")
		_, exists = vr.prevValidators[addr]
	}

	return exists
}

// prove that header is linked to verified nextHeader
// only then can header be used for receiver.Callback or vr.Update()
func (vr *Verifier) Verify(previousHeader, header *types.Header, nextHeader *types.Header, receipts types.Receipts) error {
	fmt.Println(nextHeader.Number.Cmp((&big.Int{}).Add(header.Number, big1)))
	fmt.Println(nextHeader.Number)
	if nextHeader.Number.Cmp((&big.Int{}).Add(header.Number, big1)) != 0 {
		return fmt.Errorf("Different height between successive header: Prev %v New %v", header.Number, nextHeader.Number)
	}
	if header.Hash() != nextHeader.ParentHash {
		return fmt.Errorf("Different hash between successive header: (%v): Prev %v New %v", header.Number, header.Hash(), nextHeader.ParentHash)
	}
	if vr.Next().Cmp(header.Number) != 0 {
		return fmt.Errorf("Unexpected height: Got %v Expected %v", header.Number, vr.Next())
	}
	// if header.ParentHash != vr.ParentHash() {
	// 	return fmt.Errorf("Unexpected Hash(%v): Got %v Expected %v", header.Number, header.ParentHash, vr.ParentHash())
	// }

	if err := vr.verifyHeader(nextHeader); err != nil {
		return errors.Wrapf(err, "verifyHeader %v", err)
	}
	if err := vr.verifyCascadingFields(nextHeader, header); err != nil {
		return errors.Wrapf(err, "verifyCascadingFields %v", err)
	}
	if err := vr.verifySeal(nextHeader, vr.ChainID()); err != nil {
		return errors.Wrapf(err, "verifySeal %v", err)
	}
	if len(receipts) > 0 {
		if err := vr.validateState(nextHeader, receipts); err != nil {
			return errors.Wrapf(err, "validateState %v", err)
		}
	}

	fmt.Println("before verify vote attestation")
	parents := []*types.Header{previousHeader}
	if err := vr.VerifyVoteAttestation(header, parents); err != nil {
		fmt.Println("error from vote attestation")
		fmt.Println(err)
		return err
	}
	return nil
}

func (vr *Verifier) Update(previousHeader, header *types.Header) (err error) {
	vr.mu.Lock()
	defer vr.mu.Unlock()
	fmt.Println("updating for block : ", header.Number)
	fmt.Println("updating parent header: ", previousHeader.Number)
	valAddressMap := make(map[ethCommon.Address]bool)
	valPublicKeyMap := make(map[ethCommon.Address]types.BLSPublicKey)

	if header.Number.Uint64()%defaultEpochLength == 0 || isLubanBlock(header.Number){
		newValidators, blsPubKeys, err := parseValidators(header)
		for i := 0; i < len(newValidators); i++ {
			valAddressMap[newValidators[i]] = true
			if isLubanBlock(header.Number){
				valPublicKeyMap[newValidators[i]] = blsPubKeys[i]
			}

		}
		if err != nil {
			return errors.Wrapf(err, "getValidatorMapFromHex %v", err)
		}
		// update validators only if epoch block and no error encountered
		vr.prevValidators = vr.validators
		vr.validators = valAddressMap
		vr.prevValidatorPubKey = vr.validatorPubKey
		vr.validatorPubKey = valPublicKeyMap
		vr.useNewValidatorsFromHeight = (&big.Int{}).Add(header.Number, big.NewInt(1+int64(len(vr.prevValidators)/2)))
	}
	vr.parentHash = header.Hash()
	parentHeader := make([]*types.Header, 1)
	parentHeader = append(parentHeader, previousHeader)
	vr.ParentHeader = parentHeader
	vr.next.Add(header.Number, big1)
	return
}

func parseValidators(header *types.Header) ([]ethCommon.Address, []types.BLSPublicKey, error) {
	validatorsBytes := getValidatorBytesFromHeader(header)
	fmt.Println("lenght of validators bytes is: ", len(validatorsBytes), header.Number)
	if len(validatorsBytes) == 0 {
		return nil, nil, errors.New("invalid validators bytes")
	}

	if !isLubanBlock(header.Number) {
		n := len(validatorsBytes) / validatorBytesLengthBeforeLuban
		result := make([]ethCommon.Address, n)
		for i := 0; i < n; i++ {
			result[i] = ethCommon.BytesToAddress(validatorsBytes[i*validatorBytesLengthBeforeLuban : (i+1)*validatorBytesLengthBeforeLuban])
		}
		return result, nil, nil
	}

	n := len(validatorsBytes) / validatorBytesLength
	cnsAddrs := make([]ethCommon.Address, n)
	voteAddrs := make([]types.BLSPublicKey, n)
	for i := 0; i < n; i++ {
		cnsAddrs[i] = ethCommon.BytesToAddress(validatorsBytes[i*validatorBytesLength : i*validatorBytesLength+ethCommon.AddressLength])
		copy(voteAddrs[i][:], validatorsBytes[i*validatorBytesLength+ethCommon.AddressLength:(i+1)*validatorBytesLength])
	}
	return cnsAddrs, voteAddrs, nil
}

func getValidatorBytesFromHeader(header *types.Header) []byte {
	fmt.Println("reaached in the top: ", len(header.Extra), extraVanity+extraSeal)
	if len(header.Extra) <= extraVanity+extraSeal {
			return nil
	}

	if !isLubanBlock(header.Number) {
		if header.Number.Uint64()%defaultEpochLength == 0 && (len(header.Extra)-extraSeal-extraVanity)%validatorBytesLengthBeforeLuban != 0 {
			return nil
		}
		return header.Extra[extraVanity : len(header.Extra)-extraSeal]
	}

	if header.Number.Uint64()%defaultEpochLength != 0 {
		fmt.Println("reaches here: ", isExLuban(header.Number))
		if !isExLuban(header.Number){
			fmt.Println("shoudlnot come here")
			return nil
		}
	}
	num := int(header.Extra[extraVanity])
	if num == 0 || len(header.Extra) <= extraVanity+extraSeal+num*validatorBytesLength {
		return nil
	}
	start := extraVanity + validatorNumberSize
	end := start + num*validatorBytesLength
	return header.Extra[start:end]
}

func (vr *Verifier) verifyHeader(header *types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	// if header.Time > uint64(time.Now().Unix()) {
	// 	return consensus.ErrFutureBlock
	// }
	// Check that the extra-data contains the vanity, validators and signature.
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// check extra data
	// isEpoch := number%defaultEpochLength == 0

	fmt.Println("the number is ", number)

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	fmt.Println("signers bytes of header ", header.Number, "is", signersBytes)

	// now the blocks contains attestaion feilds

	// if !isEpoch && signersBytes > attestationBytes {
	// 	return errExtraValidators
	// }

	// if isEpoch && signersBytes == 0 {
	// 	return errMissingValidators
	// }

	// validatorsBytes := signersBytes - validatorNumberSize - attestationBytes
	// fmt.Println("signers bytes of header ", header.Number, "is", validatorsBytes)

	// if isEpoch && validatorsBytes%validatorBytesLength != 0 {
	// 	return errInvalidSpanValidators
	// }

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (ethCommon.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 && header.Difficulty == nil {
		return errInvalidDifficulty
	}

	// fmt.Println("header inside the parse vote is: ", header.Number)
	// attestation, err := parseVoteAttestation(header)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println("vote attestation is: ")
	// fmt.Println(attestation)

	return nil
}

func (vr *Verifier) verifyCascadingFields(header *types.Header, parent *types.Header) error {
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	// Verify that the gas limit is <= 2^63-1
	capacity := MaxGasLimit
	if header.GasLimit > capacity {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, capacity)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / ParliaGasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	return nil
}

func (vr *Verifier) verifySeal(header *types.Header, chainID *big.Int) error {
	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, chainID)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}
	fmt.Println("Signer is ", signer)
	if ok := vr.IsValidator(signer, header.Number); !ok {
		return errUnauthorizedValidator
	}
	// TODO: check if signer is a recent Validator; avoid recent validators for spam protection
	return nil
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, chainId *big.Int) (ethCommon.Address, error) {
	if len(header.Extra) < extraSeal {
		return ethCommon.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return ethCommon.Address{}, err
	}
	var signer ethCommon.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash ethCommon.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

func (vr *Verifier) validateState(header *types.Header, receipts types.Receipts) error {
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	receiptSha := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	return nil
}

func (vr Verifier) VerifyVoteAttestation(header *types.Header, parents []*types.Header) error {

	fmt.Println("reached in verify vote attestation ")

	// we send the parent to be verified along with the next block
	// we gather the attestation data of the next block and compare it to the parents
	// we then get the bls signatures from the next header
	// we then verifiy the bls signatures with the validator set that was updated in the beginning of the cycle

	attestation, err := parseVoteAttestation(header)

	// _, blsSignatures, err := getValidatorMapFromHex(header.Extra)
	if err != nil {
		fmt.Println("error from vote attestation initially")
		return err
	}
	if attestation == nil {
		fmt.Println("not luban block reaches here: ", attestation)
		return nil
	}
	if attestation.Data == nil {
		return fmt.Errorf("invalid attestation, vote data is nil")
	}
	if len(attestation.Extra) > types.MaxAttestationExtraLength {
		return fmt.Errorf("invalid attestation, too large extra length: %d", len(attestation.Extra))
	}

	// Get parent block
	var parent *types.Header
	if len(parents) > 0 {
		fmt.Println("reached here in len greater")
		parent = parents[len(parents)-1]
	} else {
		parent = parents[len(parents)-1]
	}
	fmt.Println("Parents length", len(parents))
	fmt.Println("Parents number: ", parent.Number)
	fmt.Println("header number: ", header.Number)

	if parent == nil || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	// The target block should be direct parent.
	fmt.Println("The target block is: ", attestation.Data.TargetNumber)
	targetNumber := attestation.Data.TargetNumber
	targetHash := attestation.Data.TargetHash
	if targetNumber != parent.Number.Uint64() || targetHash != parent.Hash() {
		fmt.Println("reached in this?")
		return fmt.Errorf("invalid attestation, target mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
			parent.Number.Uint64(), parent.Hash(), targetNumber, targetHash)
	}

	// The source block should be the highest justified block.

	// n-1, n, n + 1 blocks xa. n + 1 block ko target block is n because it is the block whose votes are contained in n + 1
	// nth block ko target block will be n - 1 because same reason
	// n + 1 ko source number will be n - 1 because n - 1 is the highest justified block when n + 1 came out i.e.
	// according to the docs justified blocks are the blocks which is a root or the vote data of the block lies in the child below it.
	// when n + 1 block comes out, the highest justified block will be n - 1 because n - 1's vote data is present in the n th block which n + 1 votes for.

	sourceNumber := attestation.Data.SourceNumber
	sourceHash := attestation.Data.SourceHash

	fmt.Println(sourceNumber)
	fmt.Println(sourceHash)
	fmt.Println(attestation.Data.TargetNumber)

	fmt.Println("header of header: ", header.Number)

	fmt.Println("header of parent: ", parent.Number)

	// get justified number nad hash le parent header ma bhako attenstaion le kun block lai vote garna lako ho tyesko informantion dinxa
	// since parent le vote gareko
	justifiedBlockNumber, justifiedBlockHash, err := vr.GetJustifiedNumberAndHash(parent)

	fmt.Println("comparing the justified number and hash ")

	fmt.Println(sourceNumber, justifiedBlockNumber)
	fmt.Println(sourceHash, justifiedBlockHash)
	if err != nil {
		return fmt.Errorf("unexpected error when getting the highest justified number and hash")
	}
	if sourceNumber != justifiedBlockNumber || sourceHash != justifiedBlockHash {
		return fmt.Errorf("invalid attestation, source mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
			justifiedBlockNumber, justifiedBlockHash, sourceNumber, sourceHash)
	}

	// The snapshot should be the targetNumber-1 block's snapshot.
	if len(parents) > 1 {
		parents = parents[:len(parents)-1]
	} else {
		parents = nil
	}
	// snap, err := vr.parliaSnapshot(parent.Number.Uint64()-1, parent.ParentHash, parents)
	if err != nil {
		return err
	}

	// Filter out valid validator from attestation.
	var validators []ethCommon.Address

	for validator, _ := range vr.validators {
		// fmt.Println(validator)
		// fmt.Println(vr.validatorPubKey[validator])
		validators = append(validators, validator)
	}

	// header ko attestation data bata validator bit set nikalyo

	validatorsBitSet := bitset.From([]uint64{uint64(attestation.VoteAddressSet)})

	if validatorsBitSet.Count() > uint(len(validators)) {
		return fmt.Errorf("invalid attestation, vote number larger than validators number")
	}

	votedAddrs := make([]bls.PublicKey, 0, validatorsBitSet.Count())
	for index, val := range validators {
		if !validatorsBitSet.Test(uint(index)) {
			continue
		}
		// fmt.Println(val)
		blsPubKey := vr.validatorPubKey[val]
		// blsPubKey := blsSignatures[val]

		// fmt.Println(blsPubKey)

		// appended the public key from the vr.validator pub key
		voteAddr, err := bls.PublicKeyFromBytes(blsPubKey[:])
		if err != nil {
			return fmt.Errorf("BLS public key converts failed: %v", err)
		}
		votedAddrs = append(votedAddrs, voteAddr)
	}

	// The valid voted validators should be no less than 2/3 validators.
	if len(votedAddrs) < cmath.CeilDiv(len(vr.validators)*2, 3) {
		return fmt.Errorf("invalid attestation, not enough validators voted")
	}

	// Verify the aggregated signature.
	aggSig, err := bls.SignatureFromBytes(attestation.AggSignature[:])
	if err != nil {
		return fmt.Errorf("BLS signature converts failed: %v", err)
	}
	if !aggSig.FastAggregateVerify(votedAddrs, attestation.Data.Hash()) {
		return fmt.Errorf("invalid attestation, signature verify failed")
	}

	fmt.Println("verified the vote attestation for block ", parent.Number)

	return nil
}

func parseVoteAttestation(header *types.Header) (*types.VoteAttestation, error) {
	fmt.Println("parse vote attestation ")
	if len(header.Extra) <= extraVanity+extraSeal {
		return nil, nil
	}

	var attestationBytes []byte
	if header.Number.Uint64()%defaultEpochLength != 0 {
		attestationBytes = header.Extra[extraVanity : len(header.Extra)-extraSeal]
	} else {
		num := int(header.Extra[extraVanity])
		if len(header.Extra) <= extraVanity+extraSeal+validatorNumberSize+num*validatorBytesLength {
			return nil, nil
		}
		start := extraVanity + validatorNumberSize + num*validatorBytesLength
		end := len(header.Extra) - extraSeal
		attestationBytes = header.Extra[start:end]
	}

	var attestation types.VoteAttestation
	fmt.Println("before rlp decoded the attestation")
	if err := rlp.Decode(bytes.NewReader(attestationBytes), &attestation); err != nil {
		return nil, fmt.Errorf("block %d has vote attestation info, decode err: %s", header.Number.Uint64(), err)
	}
	fmt.Println("after the attestation")
	return &attestation, nil
}

func (vr *Verifier) GetJustifiedNumberAndHash(header *types.Header) (uint64, ethCommon.Hash, error) {
	// if header == nil {
	// 	return 0, ethCommon.Hash{}, fmt.Errorf("illegal chain or header")
	// }
	// fmt.Println("before parlia snapshot")
	// snap, err := vr.parliaSnapshot(header.Number.Uint64(), header.Hash(), nil)
	// fmt.Println("after parlia snapshot", snap)
	// if err != nil {

	// 	return 0, ethCommon.Hash{}, err
	// }

	// if snap.Attestation == nil {
	// 	return 0, header.Hash(), nil
	// }

	fmt.Println("in justified Number and hash", header.Number)

	voteAttestaionOfParent, err := parseVoteAttestation(header)
	if err != nil {
		println("error in getting vote attestation ")
	}

	fmt.Println(voteAttestaionOfParent.Data.SourceNumber)

	fmt.Println(voteAttestaionOfParent.Data.SourceHash)

	return voteAttestaionOfParent.Data.TargetNumber, voteAttestaionOfParent.Data.TargetHash, nil
}

func getValidatorsBytesFromHeader(extra []byte) []byte {
	if len(extra) != 0 {
		num := int(extra[extraVanity])
		start := extraVanity + 1
		end := start + num*68

		return extra[start:end]
	}
	return nil
}

func isLubanBlock(block *big.Int) bool {
	return block.Cmp(lubanBlockTestnet) > 0
}

func isExLuban(block *big.Int) bool {
	return block.Cmp(lubanBlockTestnet)==0
}
