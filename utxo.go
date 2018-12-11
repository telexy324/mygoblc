package main

import (
	"log"
	"encoding/gob"
	"bytes"
)

type UTXO struct {
	TxID   [] byte  //当前Transaction的交易ID
	Index  int      //下标索引
	Output *TXOutput //对txoutput做封装
}

// TXOutputs collects TXOutput
type TXOutputs struct {
	UTXOS []UTXO
}

// Serialize serializes TXOutputs
func (outs TXOutputs) Serialize() []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(outs)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

// DeserializeOutputs deserializes TXOutputs
func DeserializeOutputs(data []byte) TXOutputs {
	var outputs TXOutputs

	dec := gob.NewDecoder(bytes.NewReader(data))
	err := dec.Decode(&outputs)
	if err != nil {
		log.Panic(err)
	}

	return outputs
}
