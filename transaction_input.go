package main

import "bytes"

// TXInput represents a transaction input
type TXInput struct {
	Txid      []byte  //transaction的hash
	Vout      int	//存储TXOutput在Vout里面的索引
	Signature []byte	//签名
	PubKey    []byte	//钱包公钥，未经hash操作
}

// UsesKey checks whether the address initiated the transaction
//判断交易输入中的publickey是谁的，判断是谁发起了这个交易
func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
	lockingHash := HashPubKey(in.PubKey)  //20字节切片

	return bytes.Compare(lockingHash, pubKeyHash) == 0
}
