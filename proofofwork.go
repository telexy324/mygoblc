package main

import (
	"math"
	"math/big"
	"bytes"
	"fmt"
	"crypto/sha256"
)

//最大尝试nonce值
var (
	maxNonce = math.MaxInt64
)

//难度
const targetBits = 16


type ProofOfWork struct {
	block *Block
	target *big.Int
}

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	//左移240位,先将target转化为2进制，移位后再转化为10进制
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b,target}
	return  pow
}

//将区块中的所有数据，（不包括nonce）与需要尝试的nonce组合成一个字节数组,计算hash值，看是否满足要求
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	//bytes.Join返回将所有数组拆开，组成一个大数组返回
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.HashTransaction(),
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
		)
	return data
}

func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	fmt.Println("Mining a new block")
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data) //返回32字节的hash值
		if math.Remainder(float64(nonce),100000) == 0 {
			fmt.Printf("\r%x",hash)
		}
		hashInt.SetBytes(hash[:]) //setbytes即将字节数组按位顺序排列，每个字节8位2进制首尾排列，然后再求10进制值

		if hashInt.Cmp(pow.target) == -1 { //其实就是按位比较
			break
		} else {
			nonce ++
		}

	}
	fmt.Print("\n\n")
	return nonce,hash[:]
}

func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data :=pow.prepareData(pow.block.Nonce)
	hash:=sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}