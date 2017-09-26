import socketserver
from http.server import BaseHTTPRequestHandler

PORT = 7080  # 'py' in hex
HOST = "127.0.0.1"

WS_CLIENT_HTML = b"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta content="text/html;charset=utf-8" http-equiv="Content-Type">
    <meta content="utf-8" http-equiv="encoding">
    <title>WebSocket Client</title>
    <style>
        #output {
            border: solid 1px #000;
        }
    </style>
</head>
<body>
    <canvas 'style="border-style: solid; width: 100%; height: 100%; margin: 0;"
             id="tutorial" width="500" height="500"></canvas>

    <form id="form">
        <input type="text" id="message">
        <button type="submit">Send</button>
    </form>

    <div id="output"></div>

    <script>

        var inputBox = document.getElementById("message");
        var output = document.getElementById("output");
        var form = document.getElementById("form");

        try {

            var host = "ws://" + window.location.hostname + ":7079/";
            console.log("Host:", host);

            var s = new WebSocket(host);

            s.onopen = function (e) {
                console.log("Socket opened.");
            };

            s.onclose = function (e) {
                console.log("Socket closed.");
            };

            s.onmessage = function (e) {
                console.log("Socket message:", e.data);
                var p = document.createElement("p");
                p.innerHTML = e.data;
                output.appendChild(p);
            };

            s.onerror = function (e) {
                console.log("Socket error:", e);
            };

        } catch (ex) {
            console.log("Socket exception:", ex);
        }

        form.addEventListener("submit", function (e) {
            e.preventDefault();
            s.send(inputBox.value);
            inputBox.value = "";
        }, false)

    </script>

</body>
</html>
"""

def LoadInDefaultBrowser(html):
    """Display html in the default web browser without creating a temp file.

    Instantiates a trivial http server and calls webbrowser.open with a URL
    to retrieve html from that server.
    """

    class RequestHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            bufferSize = 1024 * 1024
            for i in range(0, len(html), bufferSize):
                self.wfile.write(html[i:i + bufferSize])

    httpd = socketserver.TCPServer((HOST, PORT), RequestHandler)
    print(f"Visit the URL http://{HOST}:{PORT}")
    print("serving at port", PORT)
    httpd.serve_forever()


def start_ws_client():
    """docstring for start_ws_client"""
    threading.Thread(
        target=LoadInDefaultBrowser, args=(WS_CLIENT_HTML, )).start()


if __name__ == '__main__':
    start_ws_client()
