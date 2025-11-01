package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/fatih/color"
)

func StartWs() {
	http.HandleFunc("/ws", websocketHandler)
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	// Check for websocket upgrade headers
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "Not a websocket handshake", http.StatusBadRequest)
		return
	}

	// Get the Sec-WebSocket-Key header
	key := r.Header.Get("Sec-WebSocket-Key")
	// The client sends this random base64 key — 16 bytes, base64-encoded — e.g.: dGhlIHNhbXBsZSBub25jZQ==

	// Simple base64 example:
	//  Original bytes:  01101000 01101001         ('h' 'i')
	//  Group into 6-bit chunks:  011010 000110 1001 00
	//  Pad with zeros:  011010 000110 100100
	//  Map to base64 chars:  a      G      k      =
	// So "hi" in base64 is "aGk="

	// Calculate accept key
	h := sha1.New()

	// From RFC 6455 Section 1.3:
	//   To derive 'Sec-WebSocket-Accept', the server has to take the value
	//   of the 'Sec-WebSocket-Key' header field and concatenate this with the
	//   string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".  The server must then
	//   take the SHA-1 hash of this concatenated value to obtain a 20-byte
	//   value.  The server then base64-encodes this 20-byte hash to produce
	//   the value for the 'Sec-WebSocket-Accept' header field.
	//
	// So we do exactly that:
	//   acceptKey = base64( SHA1( key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )
	//
	// Example:
	//   key: dGhlIHNhbXBsZSBub25jZQ==
	//   concatenated: dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11
	//   SHA1 hash (in bytes):  B3 7A 4F 2C 0B 4D 6A 8D 9C DA 51 9E 8C 9B 1A 7D 5A 5C 4F 0D
	//   base64-encoded: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
	//
	// So the server responds with:
	//   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
	//
	// This proves to the client that the server received the handshake request.
	//
	// Note that the server does not need to remember the key — it can just
	// compute the accept key on the fly.

	// This is concating, like one follows another directly, not numerical addition.
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Hijack the connection
	hijacker, _ := w.(http.Hijacker)
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// We have a raw TCP connection now!!

	fmt.Println("Received WebSocket handshake request:")
	fmt.Println(r.Method, r.RequestURI, r.Proto)
	for name, values := range r.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
		}
	}

	// Send handshake response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	bufrw.WriteString(resp)
	bufrw.Flush()
	println("WebSocket handshake completed")

	// Handle the connection in a simple loop
	handleConnection(conn)
}

func handleConnection(conn net.Conn) {
	fmt.Println("Starting to handle connection.")
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	// Start sending messages in a goroutine
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Send a simple text frame "hi"
			frame := []byte{0b1_000_0001, 0b0000_0010, 'h', 'i'} // FIN + text frame, length 2, payload "hi"
			_, err := conn.Write(frame)
			if err != nil {
				green.Printf("Error sending frame: %v\n", err)
				return
			}
			green.Println("Sent: hi")
		}
	}()

	// Handle incoming messages
	for {
		// Read frame header (2 bytes minimum)
		frameHeader := make([]byte, 2)
		conn.Read(frameHeader) // should do error checking here

		yellow.Println("Received WebSocket frame from client:")
		yellow.Printf("Frame header bytes: %08b %08b\n", frameHeader[0], frameHeader[1])

		// Parse frame header
		// the structure of the first byte is:
		// 1 bit: FIN
		// 3 bits: RSV1, RSV2, RSV3
		// 4 bits: Opcode
		fin := (frameHeader[0] & 0b1_000_0000) != 0 // only keep the FIN bit
		opcode := frameHeader[0] & 0b0_000_1111     // only keep the opcode bits
		// the structure of the second byte is:
		// 1 bit: MASK
		// 7 bits: Payload length
		masked := (frameHeader[1] & 0b1_000_0000) != 0 // only keep the MASK bit
		payloadLen := int(frameHeader[1] & 0b0_111_1111)

		yellow.Printf("FIN: %t, Opcode: %d, Masked: %t, Payload length: %d\n", fin, opcode, masked, payloadLen)

		// Handle extended payload lengths
		switch payloadLen {
		case 126:
			extLen := make([]byte, 2)
			_, err := conn.Read(extLen)
			if err != nil {
				return
			}
			payloadLen = int(extLen[0])<<8 | int(extLen[1])
		case 127: // this indicates that the length is in the next 8 bytes (64 bits)
			extLen := make([]byte, 8)
			_, err := conn.Read(extLen)
			if err != nil {
				return
			}
			// Just take the lower 32 bits for simplicity
			payloadLen = int(extLen[4])<<24 | int(extLen[5])<<16 | int(extLen[6])<<8 | int(extLen[7])
		}

		// Read mask key if present
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			_, err := conn.Read(maskKey)
			if err != nil {
				return
			}
			yellow.Printf("Mask key bytes: %v\n", maskKey)
		}

		// Read payload
		if payloadLen > 0 {
			payload := make([]byte, payloadLen)
			_, err := conn.Read(payload)
			if err != nil {
				return
			}

			// Unmask if needed
			if masked {
				for i := 0; i < len(payload); i++ {
					payload[i] ^= maskKey[i%4]
				}
			}

			// Handle different opcodes
			if opcode == 8 { // Close frame
				yellow.Println("Received close frame - closing connection")
				// Send close frame back
				closeFrame := []byte{0x88, 0x00} // FIN + close opcode, no payload
				conn.Write(closeFrame)
				return
			} else if opcode == 1 { // Text frame
				yellow.Printf("Received message: %s\n", string(payload))
			}
		}

		// If it's a close frame with no payload
		if opcode == 8 && payloadLen == 0 {
			yellow.Println("Received close frame - closing connection")
			// Send close frame back
			closeFrame := []byte{
				0b1_000_1000, // FIN + close opcode, no payload
				0b0_000_0000, // no mask, length 0
			}
			conn.Write(closeFrame)
			return
		}

		yellow.Println("---")
	}
}
