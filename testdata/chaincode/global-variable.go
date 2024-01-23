package fixtures

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
	peer "github.com/hyperledger/fabric-protos-go/peer"
)

var globalValue = ""

const constInt = 1

type globalStruct struct {
	globalint int
}

var globalStruct_test globalStruct

type BadChaincode struct{}

func (t *BadChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success([]byte("success"))
}

func (t BadChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	if fn == "setValue" {
		globalValue = args[0]
		globalStruct_test.globalint += 1
		stub.PutState("key", []byte(globalValue))
		return shim.Success([]byte("success"))
	} else if fn == "getValue" {
		value, _ := stub.GetState("key")
		return shim.Success(value)
	}
	return shim.Error("not a valid function")
}
