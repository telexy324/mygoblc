package main

import (
	"bytes"
)

// TXOutput represents a transaction output
type TXOutput struct {
	Value      int
	PubKeyHash []byte
}

// Lock signs the output
//对交易进行签名（要转给谁）（使用接收者的地址，并解码成公钥sha256并RIPEMD160后的形式）
func (out *TXOutput) Lock(address []byte) {
	pubKeyHash := Base58Decode(address) //将地址解码成公钥hash编码后的形式
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4] //去掉checksum及0x00头
	out.PubKeyHash = pubKeyHash
}

// IsLockedWithKey checks if the output can be used by the owner of the pubkey
//检查一个公钥的hash值能不能使用这个output
func (out *TXOutput) IsLockedWithKey(pubKeyHash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubKeyHash) == 0
}

// NewTXOutput create a new TXOutput
//创建新的output，由传进来的钱包地址锁定
func NewTXOutput(value int, address string) *TXOutput {
	txo := &TXOutput{value, nil}
	txo.Lock([]byte(address))

	return txo
}
