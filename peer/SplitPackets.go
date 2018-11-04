package peer

import "bytes"
import "github.com/gskartwii/go-bitstream"
import "log"
import "strings"

// SplitPacketBuffer represents a structure that accumulates every
// layer that is used to transmit the split packet.
type SplitPacketBuffer struct {
	// All ReliabilityLayer packets for this packet received so far
	ReliablePackets []*ReliablePacket
	// All RakNet layers for this packet received so far
	// IN RECEIVE ORDER, NOT SPLIT ORDER!!
	// Use ReliablePackets[i].RakNetLayer to access them in that order.
	RakNetPackets []*RakNetLayer
	// Next expected index
	NextExpectedPacket uint32
	// Number of _ordered_ splits we have received so far
	NumReceivedSplits uint32
	// Has a decoder routine started decoding this packet yet?
	HasBeenDecoded bool
	// Has received packet type yet? Set to true when the first split of this packet
	// is received
	HasPacketType bool
	PacketType    byte

	dataReader *extendedReader
	data       []byte

	// Have all splits been received?
	IsFinal bool
	// Unique ID given to each packet. Splits of the same packet have the same ID.
	UniqueID uint32
	// Total length received so far, in bytes
	RealLength uint32

	logBuffer *strings.Builder // must be a pointer because it may be copied!
	Logger    *log.Logger
}
type splitPacketList map[string](map[uint16](*SplitPacketBuffer))

func newSplitPacketBuffer(packet *ReliablePacket, context *CommunicationContext) *SplitPacketBuffer {
	reliables := make([]*ReliablePacket, int(packet.SplitPacketCount))
	raknets := make([]*RakNetLayer, 0, int(packet.SplitPacketCount))

	list := &SplitPacketBuffer{
		ReliablePackets: reliables,
		RakNetPackets:   raknets,
	}
	list.data = make([]byte, 0, uint32(packet.LengthInBits)*packet.SplitPacketCount*8)
	list.PacketType = 0xFF
	list.UniqueID = context.UniqueID
	context.UniqueID++
	list.logBuffer = new(strings.Builder)
	list.Logger = log.New(list.logBuffer, "", log.Lmicroseconds|log.Ltime)

	return list
}

func (list *SplitPacketBuffer) addPacket(packet *ReliablePacket, rakNetPacket *RakNetLayer, index uint32) {
	// Packets may be duplicated. At least I think so. Thanks UDP
	list.ReliablePackets[index] = packet
	list.RakNetPackets = append(list.RakNetPackets, rakNetPacket)
}

func (context *CommunicationContext) addSplitPacket(source string, packet *ReliablePacket, rakNetPacket *RakNetLayer) *SplitPacketBuffer {
	splitPacketId := packet.SplitPacketID
	splitPacketIndex := packet.SplitPacketIndex

	if !packet.HasSplitPacket {
		buffer := newSplitPacketBuffer(packet, context)
		buffer.addPacket(packet, rakNetPacket, 0)

		return buffer
	}

	var buffer *SplitPacketBuffer
	if context.splitPackets == nil {
		buffer = newSplitPacketBuffer(packet, context)
		context.splitPackets = splitPacketList{source: map[uint16]*SplitPacketBuffer{splitPacketId: buffer}}
	} else if context.splitPackets[source] == nil {
		buffer = newSplitPacketBuffer(packet, context)

		context.splitPackets[source] = map[uint16]*SplitPacketBuffer{splitPacketId: buffer}
	} else if context.splitPackets[source][splitPacketId] == nil {
		buffer = newSplitPacketBuffer(packet, context)

		context.splitPackets[source][splitPacketId] = buffer
	} else {
		buffer = context.splitPackets[source][splitPacketId]
	}
	buffer.addPacket(packet, rakNetPacket, splitPacketIndex)
	packet.SplitBuffer = buffer

	return buffer
}

func (context *CommunicationContext) handleSplitPacket(reliablePacket *ReliablePacket, rakNetPacket *RakNetLayer, packet *UDPPacket) (*SplitPacketBuffer, error) {
	source := packet.Source.String()

	packetBuffer := context.addSplitPacket(source, reliablePacket, rakNetPacket)
	expectedPacket := packetBuffer.NextExpectedPacket

	packetBuffer.RealLength += uint32(len(reliablePacket.SelfData))

	var shouldClose bool
	for len(packetBuffer.ReliablePackets) > int(expectedPacket) && packetBuffer.ReliablePackets[expectedPacket] != nil {
		packetBuffer.data = append(packetBuffer.data, packetBuffer.ReliablePackets[expectedPacket].SelfData...)

		expectedPacket++
		shouldClose = len(packetBuffer.ReliablePackets) == int(expectedPacket)
		packetBuffer.NextExpectedPacket = expectedPacket
	}
	if shouldClose {
		packetBuffer.IsFinal = true
		packetBuffer.dataReader = &extendedReader{bitstream.NewReader(bytes.NewReader(packetBuffer.data))}
		if reliablePacket.HasSplitPacket {
			// TODO: Use a linked list
			delete(context.splitPackets[source], reliablePacket.SplitPacketID)
		}
	}
	packetBuffer.NumReceivedSplits = expectedPacket

	if reliablePacket.SplitPacketIndex == 0 {
		packetBuffer.PacketType = reliablePacket.SelfData[0]
		packetBuffer.HasPacketType = true
	}

	packet.Logger = packetBuffer.Logger

	return packetBuffer, nil
}
