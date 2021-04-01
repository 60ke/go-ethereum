package vm

import (
	"bytes"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/60ke/go-ethereum/common"
	"github.com/60ke/go-ethereum/core/types"
	"github.com/60ke/go-ethereum/params"
	"github.com/ethereum/evmc/v7/bindings/go/evmc"
	"github.com/holiman/uint256"
)

func denyError(err error) {
	if err != nil {
		panic(err)
	}
}

// EVMC represents the reference to a common EVMC-based VM instance and
// the current execution context as required by go-ethereum design.
type EVMC struct {
	instance *evmc.VM        // The reference to the EVMC VM instance.
	env      *EVM            // The execution context.
	cap      evmc.Capability // The supported EVMC capability (EVM or Ewasm)
	readOnly bool            // The readOnly flag (TODO: Try to get rid of it).
}

var (
	evmModule   *evmc.VM
	ewasmModule *evmc.VM
)

func InitEVMCEVM(config string) {
	evmModule = initEVMC(evmc.CapabilityEVM1, config)
}

func InitEVMCEwasm(config string) {
	ewasmModule = initEVMC(evmc.CapabilityEWASM, config)
}

func initEVMC(cap evmc.Capability, config string) *evmc.VM {

	instance, err := evmc.Load(config)
	denyError(err)
	return instance
}

// hostContext implements evmc.HostContext interface.
type hostContext struct {
	env      *EVM      // The reference to the EVM execution context.
	contract *Contract // The reference to the current contract, needed by Call-like methods.
}

func (host *hostContext) AccountExists(addr common.Address) bool {
	if host.env.ChainConfig().IsEIP158(host.env.Context.BlockNumber) {
		if !host.env.StateDB.Empty(common.Address(addr)) {
			return true
		}
	} else if host.env.StateDB.Exist(common.Address(addr)) {
		return true
	}
	return false
}

func (host *hostContext) GetStorage(addr common.Address, key common.Hash) common.Hash {
	return host.env.StateDB.GetState(addr, key)
}

func (host *hostContext) SetStorage(addr common.Address, key common.Hash, value common.Hash) (status evmc.StorageStatus) {
	oldValue := host.env.StateDB.GetState(addr, key)
	if oldValue == value {
		return evmc.StorageUnchanged
	}

	current := host.env.StateDB.GetState(addr, key)
	original := host.env.StateDB.GetCommittedState(addr, key)

	host.env.StateDB.SetState(addr, key, value)

	hasNetStorageCostEIP := host.env.ChainConfig().IsConstantinople(host.env.Context.BlockNumber) &&
		!host.env.ChainConfig().IsPetersburg(host.env.Context.BlockNumber)
	if !hasNetStorageCostEIP {

		zero := common.Hash{}
		status = evmc.StorageModified
		if oldValue == zero {
			return evmc.StorageAdded
		} else if value == zero {
			host.env.StateDB.AddRefund(params.SstoreRefundGas)
			return evmc.StorageDeleted
		}
		return evmc.StorageModified
	}

	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return evmc.StorageAdded
		}
		if value == (common.Hash{}) { // delete slot (2.1.2b)
			host.env.StateDB.AddRefund(params.NetSstoreClearRefund)
			return evmc.StorageDeleted
		}
		return evmc.StorageModified
	}
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			host.env.StateDB.SubRefund(params.NetSstoreClearRefund)
		} else if value == (common.Hash{}) { // delete slot (2.2.1.2)
			host.env.StateDB.AddRefund(params.NetSstoreClearRefund)
		}
	}
	if original == value {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			host.env.StateDB.AddRefund(params.NetSstoreResetClearRefund)
		} else { // reset to original existing slot (2.2.2.2)
			host.env.StateDB.AddRefund(params.NetSstoreResetRefund)
		}
	}
	return evmc.StorageModifiedAgain
}

func (host *hostContext) GetBalance(addr common.Address) common.Hash {
	return common.BigToHash(host.env.StateDB.GetBalance(addr))
}

func (host *hostContext) GetCodeSize(addr common.Address) int {
	return host.env.StateDB.GetCodeSize(addr)
}

func (host *hostContext) GetCodeHash(addr common.Address) common.Hash {
	if host.env.StateDB.Empty(addr) {
		return common.Hash{}
	}
	return host.env.StateDB.GetCodeHash(addr)
}

func (host *hostContext) GetCode(addr common.Address) []byte {
	return host.env.StateDB.GetCode(addr)
}

func (host *hostContext) Selfdestruct(addr common.Address, beneficiary common.Address) {
	db := host.env.StateDB
	if !db.HasSuicided(addr) {
		db.AddRefund(params.SelfdestructRefundGas)
	}
	db.AddBalance(beneficiary, db.GetBalance(addr))
	db.Suicide(addr)
}

func (host *hostContext) GetTxContext() evmc.TxContext {
	var gasPrice [32]byte = common.BigToHash(host.env.TxContext.GasPrice)
	var origin [20]byte = host.env.TxContext.Origin
	var coinbase = (*common.Address)(unsafe.Pointer(&host.env.Context.Coinbase))

	return evmc.TxContext{
		GasPrice:   gasPrice,
		Origin:     origin,
		Coinbase:   *coinbase,
		Number:     host.env.Context.BlockNumber.Int64(),
		Timestamp:  host.env.Context.Time.Int64(),
		GasLimit:   int64(host.env.Context.GasLimit),
		Difficulty: common.BigToHash(host.env.Context.Difficulty)}
}

func (host *hostContext) GetBlockHash(number int64) common.Hash {
	b := host.env.Context.BlockNumber.Int64()
	if number >= (b-256) && number < b {
		return host.env.Context.GetHash(uint64(number))
	}
	return common.Hash{}
}

func (host *hostContext) EmitLog(addr common.Address, topics []common.Hash, data []byte) {
	host.env.StateDB.AddLog(&types.Log{
		Address:     addr,
		Topics:      topics,
		Data:        data,
		BlockNumber: host.env.Context.BlockNumber.Uint64(),
	})
}

func (host *hostContext) Call(kind evmc.CallKind,
	destination common.Address, sender common.Address, value *big.Int, input []byte, gas int64, depth int,
	static bool, salt *big.Int) (output []byte, gasLeft int64, createAddr common.Address, err error) {

	gasU := uint64(gas)
	var gasLeftU uint64

	switch kind {
	case evmc.Call:
		if static {
			output, gasLeftU, err = host.env.StaticCall(host.contract, destination, input, gasU)
		} else {
			output, gasLeftU, err = host.env.Call(host.contract, destination, input, gasU, value)
		}
	case evmc.DelegateCall:
		output, gasLeftU, err = host.env.DelegateCall(host.contract, destination, input, gasU)
	case evmc.CallCode:
		output, gasLeftU, err = host.env.CallCode(host.contract, destination, input, gasU, value)
	case evmc.Create:
		var createOutput []byte
		createOutput, createAddr, gasLeftU, err = host.env.Create(host.contract, input, gasU, value)
		isHomestead := host.env.ChainConfig().IsHomestead(host.env.Context.BlockNumber)
		if !isHomestead && err == ErrCodeStoreOutOfGas {
			err = nil
		}
		if err == ErrExecutionReverted {
			// Assign return buffer from REVERT.
			// TODO: Bad API design: return data buffer and the code is returned in the same place. In worst case
			//       the code is returned also when there is not enough funds to deploy the code.
			output = createOutput
		}
	case evmc.Create2:
		var createOutput []byte
		salt256, ret := uint256.FromBig(salt)
		if ret {
			panic("salt convert to u256 overflow")
		}
		createOutput, createAddr, gasLeftU, err = host.env.Create2(host.contract, input, gasU, value, salt256)
		if err == ErrExecutionReverted {
			// Assign return buffer from REVERT.
			// TODO: Bad API design: return data buffer and the code is returned in the same place. In worst case
			//       the code is returned also when there is not enough funds to deploy the code.
			output = createOutput
		}
	default:
		panic(fmt.Errorf("EVMC: Unknown call kind %d", kind))
	}

	// Map errors.

	// if err == errExecutionReverted {

	// 	err = evmc.Revert
	// } else if err != nil {
	// 	err = evmc.Failure
	// }

	gasLeft = int64(gasLeftU)
	return output, gasLeft, createAddr, err
}

// getRevision translates ChainConfig's HF block information into EVMC revision.
func getRevision(env *EVM) evmc.Revision {
	n := env.Context.BlockNumber
	conf := env.ChainConfig()
	switch {
	case conf.IsPetersburg(n):
		return evmc.Petersburg
	case conf.IsConstantinople(n):
		return evmc.Constantinople
	case conf.IsByzantium(n):
		return evmc.Byzantium
	case conf.IsEIP158(n):
		return evmc.SpuriousDragon
	case conf.IsEIP150(n):
		return evmc.TangerineWhistle
	case conf.IsHomestead(n):
		return evmc.Homestead
	default:
		return evmc.Frontier
	}
}

// Run implements Interpreter.Run().
func (evm *EVMC) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	evm.env.depth++
	defer func() { evm.env.depth-- }()

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	kind := evmc.Call
	if evm.env.StateDB.GetCodeSize(contract.Address()) == 0 {
		// Guess if this is a CREATE.
		kind = evmc.Create
	}

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This makes also sure that the readOnly flag isn't removed for child calls.
	if readOnly && !readOnly {
		readOnly = true
		defer func() { readOnly = false }()
	}

	output, gasLeft, err := evm.instance.Execute(
		&hostContext{evm.env, contract},
		getRevision(evm.env),
		kind,
		readOnly,
		evm.env.depth-1,
		int64(contract.Gas),
		common.Address(contract.Address()),
		common.Address(contract.Caller()),
		input,
		common.BigToHash(contract.value),
		contract.Code,
		common.Hash{})

	contract.Gas = uint64(gasLeft)

	if err == evmc.Revert {
		err = fmt.Errorf("errExecutionReverted")
	} else if evmcError, ok := err.(evmc.Error); ok && evmcError.IsInternalError() {
		panic(fmt.Sprintf("EVMC VM internal error: %s", evmcError.Error()))
	}

	return output, err
}

// CanRun implements Interpreter.CanRun().
func (evm *EVMC) CanRun(code []byte) bool {
	required := evmc.CapabilityEVM1
	wasmPreamble := []byte("\x00asm")
	if bytes.HasPrefix(code, wasmPreamble) {
		required = evmc.CapabilityEWASM
	}
	return evm.cap == required
}
