/*
 * Copyright (c) 2021 ugradid community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package logic

import (
	"github.com/ugradid/ugradid-node/crypto/hash"
	"github.com/ugradid/ugradid-node/network/dag"
	"github.com/ugradid/ugradid-node/network/log"
	"github.com/ugradid/ugradid-node/network/transport"
	"github.com/ugradid/ugradid-node/network/transport/v1/p2p"
	"github.com/ugradid/ugradid-node/network/transport/v1/protobuf"
	"google.golang.org/protobuf/proto"
	"math"
	"time"
)

// estimatedMessageSizeMargin defines the factor by which the message size is multiplied, as a safety measure to avoid
// accidentally exceeding the max Protobuf message size.
const estimatedMessageSizeMargin = 0.75

// messageSender provides a domain-specific abstraction for sending messages to the network. It aids testing and
// implementation of non-functional requirements like throttling.
type messageSender interface {
	broadcastAdvertHashes(blocks []dagBlock)
	broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash)
	sendTransactionListQuery(peer transport.PeerId, blockDate time.Time)
	sendTransactionList(peer transport.PeerId, transactions []dag.Transaction, date time.Time)
	sendTransactionPayloadQuery(peer transport.PeerId, payloadHash hash.SHA256Hash)
	sendTransactionPayload(peer transport.PeerId, payloadHash hash.SHA256Hash, data []byte)
}

type defaultMessageSender struct {
	p2p                    p2p.Adapter
	maxMessageSize         int
	transactionsPerMessage int
}

func (s defaultMessageSender) doSend(peer transport.PeerId, envelope *protobuf.NetworkMessage) {
	if err := s.p2p.Send(peer, envelope); err != nil {
		log.Logger().Warnf("Error while sending message to peer (peer=%s, msg=%T): %v", peer, envelope.Message, err)
	}
}

func (s defaultMessageSender) broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash) {
	s.p2p.Broadcast(createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) broadcastAdvertHashes(blocks []dagBlock) {
	envelope := createEnvelope()
	envelope.Message = createAdvertHashesMessage(blocks)
	s.p2p.Broadcast(&envelope)
}

func (s defaultMessageSender) sendTransactionListQuery(peer transport.PeerId, blockDate time.Time) {
	envelope := createEnvelope()
	timestamp := int64(0)
	if !blockDate.IsZero() {
		timestamp = blockDate.Unix()
	}
	envelope.Message = &protobuf.NetworkMessage_TransactionListQuery{
		TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: uint32(timestamp)}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionList(peer transport.PeerId, transactions []dag.Transaction, blockDate time.Time) {
	if len(transactions) == 0 {
		// messages are asynchronous so the requester is not waiting for a response
		return
	}
	// When the DAG grows it the transactions might not fit in 1 network message (defined by p2p.MaxMessageSizeInBytes),
	// so we have to split it up in pages. Protobuf can calculate the size of a message, so we can check whether it will fit in the max. message size.
	// However, this can be quite expensive since it will marshal the message to the wire format (thus, marshalling will happen twice).
	// Furthermore, we'd have to do this for every transaction we add to the message to find the max. number of TXs that
	// will fit in the message.
	// Since this sounds all horribly inefficient, we just calculate the size of a network message with 1 transaction,
	// and use that to guesstimate the number of transactions that will fit in a message, decreased by a safety margin.
	// Since transactions just contain metadata of the transaction (and not the payload itself), all transactions should
	// serialize to more or less the same number of bytes, making the calculation safe.
	transactionsPerMessage := s.getTransactionsPerMessage(transactions)
	numberOfMessages := int(math.Ceil(float64(len(transactions)) / float64(transactionsPerMessage)))
	tl := toNetworkTransactions(transactions)

	for i := 0; i < numberOfMessages; i++ {
		upper := (i + 1) * transactionsPerMessage
		if upper > len(tl) {
			upper = len(tl)
		}
		envelope := createEnvelope()
		envelope.Message = &protobuf.NetworkMessage_TransactionList{
			TransactionList: &protobuf.TransactionList{
				Transactions: tl[i*transactionsPerMessage : upper],
				BlockDate: uint32(blockDate.Unix())}}
		s.doSend(peer, &envelope)
	}
}

func (s defaultMessageSender) sendTransactionPayloadQuery(peer transport.PeerId, payloadHash hash.SHA256Hash) {
	s.doSend(peer, createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) sendTransactionPayload(peer transport.PeerId, payloadHash hash.SHA256Hash, data []byte) {
	envelope := createEnvelope()
	envelope.Message = &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        data,
	}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) getTransactionsPerMessage(transactions []dag.Transaction) int {
	if s.transactionsPerMessage != 0 {
		return s.transactionsPerMessage
	}

	sizeMsg := createEnvelope()
	sizeMsg.Message = &protobuf.NetworkMessage_TransactionList{TransactionList: &protobuf.TransactionList{Transactions: toNetworkTransactions([]dag.Transaction{transactions[0]}), BlockDate: uint32(time.Now().Unix())}}
	messageSizePerTX := proto.Size(sizeMsg.ProtoReflect().Interface())
	s.transactionsPerMessage = int(math.Floor(float64(s.maxMessageSize) * estimatedMessageSizeMargin / float64(messageSizePerTX)))
	return s.transactionsPerMessage
}

func createEnvelope() protobuf.NetworkMessage {
	return protobuf.NetworkMessage{}
}

func createTransactionPayloadQueryMessage(payloadHash hash.SHA256Hash) *protobuf.NetworkMessage {
	envelope := createEnvelope()
	envelope.Message = &protobuf.NetworkMessage_TransactionPayloadQuery{
		TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()},
	}
	return &envelope
}