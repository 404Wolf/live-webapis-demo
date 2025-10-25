# Web APIs

What is a WebAPI?

https://developer.mozilla.org/en-US/docs/Web/API

![Web Vibration API](https://static.404wolf.com/web-vibration.png)

The syscalls of the internet!

# Fetching Weather Data

```javascript
fetch('https://wttr.in/Cleveland?format=j1')
  .then(response => response.json())
  .then(data => {
    const current = data.current_condition[0];
    console.log(`Temperature: ${current.temp_C}°C`);
    console.log(`Weather: ${current.weatherDesc[0].value}`);
  })
  .catch(error => console.error('Error:', error));
```

# Recall HTTP

```http
GET /api/users/123 HTTP/1.1\r\n
Host: example.com\r\n
Accept: application/json\r\n
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n
User-Agent: Mozilla/5.0\r\n
\r\n
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
Content-Length: 85\r\n
\r\n
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com"
}
```

# SSE


# WebSockets

RFC nitty gritty!

```
Opcode:  4 bits

    Defines the interpretation of the "Payload data".  If an unknown
    opcode is received, the receiving endpoint MUST _Fail the
    WebSocket Connection_.  The following values are defined.

    *  %x0 denotes a continuation frame
    *  %x1 denotes a text frame
    *  %x2 denotes a binary frame
    *  %x3-7 are reserved for further non-control frames
    *  %x8 denotes a connection close
    *  %x9 denotes a ping
    *  %xA denotes a pong
    *  %xB-F are reserved for further control frames
```