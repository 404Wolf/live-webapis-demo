package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"
)

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

		// And now we can send "hi" every second

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Create websocket frame for text message "hi"

			fmt.Printf("Sending frame bytes: %v\n", []byte{0x81, 0x02, 'h', 'i'})
			// 0x81 0x02  'h' 'i'

			println("Payload bytes:", []byte("hi"))

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
			println("Mask key bytes:", mask_key)

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
			println("Masked payload bytes:", masked_payload)

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

			// Send the frame
			conn.Write(frame)
		}
	}
}

func main() {
	http.HandleFunc("/ws", websocketHandler)

	fmt.Println("WebSocket server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
