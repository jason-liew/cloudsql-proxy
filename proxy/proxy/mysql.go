package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pingcap/parser/mysql"
)

type handshakeResponse41 struct {
	Capability uint32
	Collation  uint8
	User       string
	DBName     string
	Auth       []byte
	Attrs      map[string]string
}

func parshHandshakeInfo(data []byte) (resp *handshakeResponse41, err error) {

	resp, err = readOptionalSSLRequestAndHandshakeResponse(context.Background(), data[4:])

	return
}

func readOptionalSSLRequestAndHandshakeResponse(ctx context.Context, data []byte) (resp1 *handshakeResponse41, err error) {
	// Read a packet. It may be a SSLRequest or HandshakeResponse.
	//	data, err := cc.readPacket()
	//	if err != nil {
	//		return err
	//	}
	//   var err error
	isOldVersion := false

	var resp handshakeResponse41
	var pos int

	if len(data) < 2 {
		//	logutil.Logger(ctx).Error("got malformed handshake response", zap.ByteString("packetData", data))
		fmt.Printf("got malformed handshake response %v", data)
		return nil, mysql.ErrMalformPacket
	}

	capability := uint32(binary.LittleEndian.Uint16(data[:2]))
	if capability&mysql.ClientProtocol41 > 0 {
		fmt.Printf("new version header \n")
		pos, err = parseHandshakeResponseHeader(ctx, &resp, data)
	} else {
		fmt.Printf("old version header \n")
		pos, err = parseOldHandshakeResponseHeader(ctx, &resp, data)
		isOldVersion = true
	}

	if err != nil {
		return nil, err
	}

	// Read the remaining part of the packet.
	if isOldVersion {
		fmt.Printf("old version body \n")
		err = parseOldHandshakeResponseBody(ctx, &resp, data, pos)
	} else {
		fmt.Printf("new version body \n")
		err = parseHandshakeResponseBody(ctx, &resp, data, pos)
	}
	if err != nil {
		fmt.Printf("new version error %v", err)
		return nil, err
	}
	//	err = cc.openSessionAndDoAuth(resp.Auth)
	return &resp, err
}

// parseHandshakeResponseHeader parses the common header of SSLRequest and HandshakeResponse41.
func parseHandshakeResponseHeader(ctx context.Context, packet *handshakeResponse41, data []byte) (parsedBytes int, err error) {
	// Ensure there are enough data to read:
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	if len(data) < 4+4+1+23 {
		//	logutil.Logger(ctx).Error("got malformed handshake response", zap.ByteString("packetData", data))
		//	fmt.Printf("got malformed handshake response %v", data)
		return 0, mysql.ErrMalformPacket
	}

	offset := 0
	// capability
	capability := binary.LittleEndian.Uint32(data[:4])
	packet.Capability = capability
	offset += 4
	// skip max packet size
	offset += 4
	// charset, skip, if you want to use another charset, use set names
	packet.Collation = data[offset]
	offset++
	// skip reserved 23[00]
	offset += 23

	return offset, nil
}

// parseHandshakeResponseBody parse the HandshakeResponse (except the common header part).
func parseHandshakeResponseBody(ctx context.Context, packet *handshakeResponse41, data []byte, offset int) (err error) {
	defer func() {
		// Check malformat packet cause out of range is disgusting, but don't panic!
		if r := recover(); r != nil {
			fmt.Printf("handshake panic %v \n", data)
			err = mysql.ErrMalformPacket
		}
	}()
	// user name
	packet.User = string(data[offset : offset+bytes.IndexByte(data[offset:], 0)])
	//	fmt.Printf("packet user %s \n", packet.User)

	offset += len(packet.User) + 1

	if packet.Capability&mysql.ClientPluginAuthLenencClientData > 0 {
		// MySQL client sets the wrong capability, it will set this bit even server doesn't
		// support ClientPluginAuthLenencClientData.
		// https://github.com/mysql/mysql-server/blob/5.7/sql-common/client.c#L3478
		num, null, off := parseLengthEncodedInt(data[offset:])
		offset += off
		if !null {
			packet.Auth = data[offset : offset+int(num)]
			offset += int(num)
		}
	} else if packet.Capability&mysql.ClientSecureConnection > 0 {
		// auth length and auth
		authLen := int(data[offset])
		offset++
		packet.Auth = data[offset : offset+authLen]
		offset += authLen
	} else {
		packet.Auth = data[offset : offset+bytes.IndexByte(data[offset:], 0)]
		offset += len(packet.Auth) + 1
	}

	if packet.Capability&mysql.ClientConnectWithDB > 0 {
		if len(data[offset:]) > 0 {
			idx := bytes.IndexByte(data[offset:], 0)
			packet.DBName = string(data[offset : offset+idx])
			offset = offset + idx + 1
		}
	}

	if packet.Capability&mysql.ClientPluginAuth > 0 {
		// TODO: Support mysql.ClientPluginAuth, skip it now
		idx := bytes.IndexByte(data[offset:], 0)
		offset = offset + idx + 1
	}

	if packet.Capability&mysql.ClientConnectAtts > 0 {
		if len(data[offset:]) == 0 {
			// Defend some ill-formated packet, connection attribute is not important and can be ignored.
			return nil
		}
		if num, null, off := parseLengthEncodedInt(data[offset:]); !null {
			offset += off
			row := data[offset : offset+int(num)]
			attrs, err := parseAttrs(row)
			if err != nil {
				//	logutil.Logger(ctx).Warn("parse attrs failed", zap.Error(err))
				fmt.Printf("handshake panic %v \n", data)
				return nil
			}
			packet.Attrs = attrs
		}
	}

	return nil
}

// parseOldHandshakeResponseHeader parses the old version handshake header HandshakeResponse320
func parseOldHandshakeResponseHeader(ctx context.Context, packet *handshakeResponse41, data []byte) (parsedBytes int, err error) {
	// Ensure there are enough data to read:
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse320
	//logutil.Logger(ctx).Debug("try to parse hanshake response as Protocol::HandshakeResponse320", zap.ByteString("packetData", data))
	fmt.Printf("try to parse hanshake response as Protocol::HandshakeResponse320 %x \n", data)
	if len(data) < 2+3 {
		//logutil.Logger(ctx).Error("got malformed handshake response", zap.ByteString("packetData", data))
		fmt.Printf("got malformed handshake response %v \n", data)
		return 0, mysql.ErrMalformPacket
	}
	offset := 0
	// capability
	capability := binary.LittleEndian.Uint16(data[:2])

	packet.Capability = uint32(capability)

	// be compatible with Protocol::HandshakeResponse41
	packet.Capability = packet.Capability | mysql.ClientProtocol41

	offset += 2
	// skip max packet size
	offset += 3
	// usa default CharsetID
	packet.Collation = mysql.CollationNames["utf8mb4_general_ci"]

	return offset, nil
}

// parseOldHandshakeResponseBody parse the HandshakeResponse for Protocol::HandshakeResponse320 (except the common header part).
func parseOldHandshakeResponseBody(ctx context.Context, packet *handshakeResponse41, data []byte, offset int) (err error) {
	defer func() {
		// Check malformat packet cause out of range is disgusting, but don't panic!
		if r := recover(); r != nil {
			//	logutil.Logger(ctx).Error("handshake panic", zap.ByteString("packetData", data))
			fmt.Printf("handshake panic %v \n", data)
			err = mysql.ErrMalformPacket
		}
	}()
	// user name
	//offset = 36
	packet.User = string(data[offset : offset+bytes.IndexByte(data[offset:], 0)])
	offset += len(packet.User) + 1
	fmt.Printf("packet user %v \n", []byte(packet.User))
	if packet.Capability&mysql.ClientConnectWithDB > 0 {
		if len(data[offset:]) > 0 {
			idx := bytes.IndexByte(data[offset:], 0)
			packet.DBName = string(data[offset : offset+idx])
			offset = offset + idx + 1
		}
		if len(data[offset:]) > 0 {
			packet.Auth = data[offset : offset+bytes.IndexByte(data[offset:], 0)]
		}
	} else {
		packet.Auth = data[offset : offset+bytes.IndexByte(data[offset:], 0)]
	}

	return nil
}

func parseAttrs(data []byte) (map[string]string, error) {
	attrs := make(map[string]string)
	pos := 0
	for pos < len(data) {
		key, _, off, err := parseLengthEncodedBytes(data[pos:])
		if err != nil {
			return attrs, err
		}
		pos += off
		value, _, off, err := parseLengthEncodedBytes(data[pos:])
		if err != nil {
			return attrs, err
		}
		pos += off

		attrs[string(key)] = string(value)
	}
	return attrs, nil
}

func parseLengthEncodedInt(b []byte) (num uint64, isNull bool, n int) {
	switch b[0] {
	// 251: NULL
	case 0xfb:
		n = 1
		isNull = true
		return

	// 252: value of following 2
	case 0xfc:
		num = uint64(b[1]) | uint64(b[2])<<8
		n = 3
		return

	// 253: value of following 3
	case 0xfd:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16
		n = 4
		return

	// 254: value of following 8
	case 0xfe:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 |
			uint64(b[4])<<24 | uint64(b[5])<<32 | uint64(b[6])<<40 |
			uint64(b[7])<<48 | uint64(b[8])<<56
		n = 9
		return
	}

	// 0-250: value of first byte
	num = uint64(b[0])
	n = 1
	return
}

func parseLengthEncodedBytes(b []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := parseLengthEncodedInt(b)
	if num < 1 {
		return nil, isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return b[n-int(num) : n], false, n, nil
	}

	return nil, false, n, io.EOF
}
