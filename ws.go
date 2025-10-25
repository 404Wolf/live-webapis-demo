package main

import (
	"crypto/rand"
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

		// Send handshake response
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

		bufrw.WriteString(resp)
		bufrw.Flush()
		println("WebSocket handshake completed")

		// Create termination channel and start handling connection
		terminationChan := make(chan struct{})

		// Start message sending loop
		go sendMessages(conn, terminationChan)

		// Start goroutine to handle incoming messages
		go handleIncomingMessages(conn, terminationChan)

		// Wait for termination signal and cleanup
		<-terminationChan
		terminate(conn)
	}
}

func handleIncomingMessages(conn net.Conn, terminationChan chan struct{}) {
	fmt.Println("Starting to handle incoming messages.")
	yellow := color.New(color.FgYellow)

	for {
		select {
		case <-terminationChan:
			yellow.Println("Termination signal received, stopping message handling.")
			return
		default:
		}

		// Read incoming WebSocket frame
		frameHeader := make([]byte, 2)
		_, err := conn.Read(frameHeader)
		if err != nil {
			yellow.Printf("Error reading frame header: %v\n", err)
			yellow.Println("Client disconnected, signaling termination.")
			close(terminationChan)
			return
		}

		yellow.Println("Received WebSocket frame from client:")

		// Print frame header bytes in binary
		yellow.Printf("Frame header bytes: %08b %08b\n", frameHeader[0], frameHeader[1])

		// Parse frame header
		// We want to extract:
		//   FIN: 1 bit (bit 7 of byte 0)
		//   Opcode: 4 bits (bits 0-3 of byte 0)
		//   Masked: 1 bit (bit 7 of byte 1)
		//   Payload length: 7 bits (bits 0-6 of byte 1)
		fin := (frameHeader[0] & 0b1000_0000) != 0 // check FIN bit

		opcode := frameHeader[0] & 0b0000_1111          // 0nly keep the last 4 bits
		masked := (frameHeader[1] & 0b1000_0000) != 0   // check if MASK bit is set
		payloadLen := int(frameHeader[1] & 0b0111_1111) // keep last 7 bits

		yellow.Printf("FIN: %t, Opcode: %d, Masked: %t, Payload length: %d\n", fin, opcode, masked, payloadLen)

		// Handle extended payload length if needed
		//
		// 0–125	Actual payload length (in bytes)
		// 126	Extended payload length follows — 16 bits (2 bytes) unsigned integer
		// 127	Extended payload length follows — 64 bits (8 bytes) unsigned integer
		switch payloadLen {
		case 126:
			extLen := make([]byte, 2)
			_, err := conn.Read(extLen)
			if err != nil {
				yellow.Printf("Error reading extended length: %v\n", err)
				close(terminationChan)
				return
			}
			payloadLen = int(extLen[0])<<8 | int(extLen[1])
			yellow.Printf("Extended payload length (16-bit): %d\n", payloadLen)
		case 127:
			extLen := make([]byte, 8)
			_, err := conn.Read(extLen)
			if err != nil {
				yellow.Printf("Error reading extended length: %v\n", err)
				close(terminationChan)
				return
			}
			// Convert 8-byte array to 64-bit integer (big-endian)
			payloadLen := uint64(extLen[0])<<56 | uint64(extLen[1])<<48 | uint64(extLen[2])<<40 | uint64(extLen[3])<<32 |
				uint64(extLen[4])<<24 | uint64(extLen[5])<<16 | uint64(extLen[6])<<8 | uint64(extLen[7])
			// Putting the bytes in the right places
			yellow.Printf("Extended payload length (64-bit): %d\n", payloadLen)
		}

		// Read mask key if present
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			_, err := conn.Read(maskKey)
			if err != nil {
				yellow.Printf("Error reading mask key: %v\n", err)
				close(terminationChan)
				return
			}
			yellow.Printf("Mask key bytes: %v\n", maskKey)
		}

		// Read payload
		payload := make([]byte, payloadLen)
		maskedPayload := make([]byte, payloadLen)

		if payloadLen > 0 {
			_, err := conn.Read(payload)
			if err != nil {
				yellow.Printf("Error reading payload: %v\n", err)
				close(terminationChan)
				return
			}
			copy(maskedPayload, payload)
			yellow.Printf("Masked payload bytes: %v\n", maskedPayload)

			// Unmask payload if masked
			if masked {
				for i := 0; i < len(payload); i++ {
					payload[i] ^= maskKey[i%4]
				}
			}

			yellow.Printf("Unmasked payload bytes: %v\n", payload)
			yellow.Printf("Unmasked payload binary: ")
			for _, b := range payload {
				yellow.Printf("%08b ", b)
			}
			yellow.Println()

			// Handle different frame types
			if opcode == 1 && fin { // Text frame
				yellow.Printf("Received message: %s\n", string(payload))
			} else if opcode == 8 { // Close frame
				yellow.Println("Received close frame from client")
				terminate(conn)
				return
			} else if opcode == 9 { // Ping frame
				yellow.Println("Received ping frame from client")
				// Send pong frame (opcode 10)
				pongFrame := []byte{0b1_000_1010, 0b0_000_0000} // FIN + pong opcode, no payload
				conn.Write(pongFrame)
				yellow.Println("Sent pong frame to client")
			} else if opcode == 10 { // Pong frame
				yellow.Println("Received pong frame from client")
			} else {
				yellow.Printf("Unhandled opcode: %d\n", opcode)
			}
		}

		yellow.Println("---")
	}
}

// sendMessages handles the message sending loop in a separate goroutine
func sendMessages(conn net.Conn, terminationChan chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	green := color.New(color.FgGreen)

	for {
		select {
		case <-terminationChan:
			green.Println("Termination signal received, stopping message sending.")
			return
		case <-ticker.C:
			// Create websocket frame for text message "hi"
			green.Println("Sending WebSocket frame to client:")
			green.Printf("Sending frame bytes: %v\n", []byte{0x81, 0x02, 'h', 'i'})
			// 0x81 0x02  'h' 'i'

			// Payload bytes: 01101000 01101001         ('h' 'i')
			// since:
			//   'h' = 104 = 01101000
			//   'i' = 105 = 01101001
			green.Printf("Payload bytes: %08b %08b\n", 'h', 'i')

			// Why do we do masking?
			// From RFC 6455 Section 5.1:
			//   A server MUST NOT mask any frames that it sends to the client.
			//   A client MUST mask all frames that it sends to the server.
			//
			// This is to prevent certain proxy cache poisoning attacks.
			//
			// Ok so what does this mean?
			//
			// When we are sending data over the wire, we just want to make sure that
			// the data is unpredictable.

			// Mask key:         37 FA 21 3D          (4 random bytes)
			// Generate random mask key (4 bytes)
			mask_key := make([]byte, 4)
			rand.Read(mask_key)
			green.Printf("Mask key bytes: %08b %08b %08b %08b\n", mask_key[0], mask_key[1], mask_key[2], mask_key[3])

			// Masked payload:
			//   byte 0: 68 XOR 37 = 5F
			//   byte 1: 69 XOR FA = 93
			// Masked payload bytes: 5F 93
			masked_payload := make([]byte, 2)
			payload := []byte("hi")
			for i := 0; i < len(payload); i++ {
				// We are transforming byte i of payload to be byte i of payload XOR mask_key[i % 4]
				masked_payload[i] = payload[i] ^ mask_key[i%4]
			}
			green.Printf("Masked payload bytes: %08b %08b\n", masked_payload[0], masked_payload[1])

			// 0x81: FIN + text frame
			// since 1000 0001
			//   7   6   5   4   3   2   1   0   (bit positions)
			// +---+---+---+---+---+---+---+---+
			// |FIN|RSV1/RSV2/RSV3|  OPCODE(4b) |
			// +---+---+---+---+---+---+---+---+

			// 0x02: payload length (2 bytes for "hi")
			// since 0000 0010
			//   7   6   5   4   3   2   1   0   (bit positions)
			// +---+---+---+---+---+---+---+---+
			// |MASK|     PAYLOAD LENGTH (7b)   |
			// +---+---+---+---+---+---+---+---+

			// Construct the frame manually
			frame := make([]byte, 8) // 1 + 1 + 4 + 2 = 8 bytes total

			// FIN=1, RSV1-3=0, OPCODE=0001 (text frame)
			frame[0] = 0b_1_000_0001 // FIN + text frame opcode

			// MASK=1, payload length=2
			frame[1] = 0b_1000_0010 // MASK bit + payload length (2)

			// Copy mask key (4 bytes)
			frame[2] = mask_key[0]
			frame[3] = mask_key[1]
			frame[4] = mask_key[2]
			frame[5] = mask_key[3]

			// Copy masked payload (2 bytes)
			frame[6] = masked_payload[0]
			frame[7] = masked_payload[1]

			green.Printf("Frame bytes: %08b %08b %08b %08b %08b %08b %08b %08b\n",
				frame[0], frame[1], frame[2], frame[3],
				frame[4], frame[5], frame[6], frame[7])

			green.Printf("Sending message: hi\n")
			green.Println("---")

			// Send the frame - check for errors and terminate if connection is broken
			_, err := conn.Write(frame)
			if err != nil {
				green.Printf("Error sending frame: %v\n", err)
				close(terminationChan)
				return
			}
		}
	}
}

// terminate handles the graceful shutdown of the WebSocket connection
func terminate(conn net.Conn) {
	red := color.New(color.FgRed)
	red.Println("Terminating WebSocket connection...")

	// Send close frame to client (opcode 8)

	// Bytes look like:
	// 1000 1000 0000 0000
	// ^    ^    ^
	// |    |    +-- Payload length = 0
	// |    +------- Opcode = 8 (connection close)
	// +------------ FIN = 1
	closeFrameWithReason := []byte{
		0x88, 0x04, // FIN + close opcode, payload length = 4
		0x03, 0xE8, // Status code 1000 (normal closure)
		'O', 'K', // Optional reason text
	}
	red.Printf("Sending close frame bytes: %v\n", closeFrameWithReason)

	_, err := conn.Write(closeFrameWithReason)
	if err != nil {
		red.Printf("Error sending close frame: %v\n", err)
	} else {
		red.Println("Close frame sent to client")
	}

	// Give some time for the close frame to be sent
	// Option 1: Set a write deadline and flush buffers
	conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite() // Half-close to signal we're done sending
	}

	// Close the connection
	err = conn.Close()
	if err != nil {
		red.Printf("Error closing connection: %v\n", err)
	} else {
		red.Println("WebSocket connection closed successfully")
	}
}
