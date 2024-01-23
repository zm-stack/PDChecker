package fixtures

// 检测go并发的API（转IR后的结构）
/* 匹配特征：
*  1. 链码中不应使用并发操作
 */

import (
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	peer "github.com/hyperledger/fabric-protos-go/peer"
)

type BadChaincode struct {
}

func (t *BadChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success([]byte("success"))
}

func (t *BadChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	key := "key"
	data := "data"
	data2 := "data2"
	go stub.PutState(key, []byte(data))
	go stub.PutState(key, []byte(data2))
	return shim.Success([]byte("success"))

	ch := make(chan string)

	go sendData(ch)
	go receiveData(ch)

	time.Sleep(time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go increment(&wg)
	}
	wg.Wait()
	fmt.Println("Counter:", counter)
}

func sendData(ch chan string) {
	ch <- "Hello"
	ch <- "World"
	close(ch) // 关闭通道
}

func receiveData(ch chan string) {
	for message := range ch {
		fmt.Println(message)
	}
}

func increment(wg *sync.WaitGroup) {
	mutex.Lock()
	counter++
	mutex.Unlock()
	wg.Done()
}
