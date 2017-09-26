""" tinyws: a tiny WebSocket implementation """
import socket
import hashlib
import threading
from base64 import b64encode
from enum import IntEnum
import codecs


clients = []
PORT = 7079  # 'py' in hex

"""WebSocket Close Codes"""
ERROR_NONE = 1000
ERROR_PEER = 1001
ERROR_PROTO = 1002
ERROR_BAD = 1003
ERROR_RSV = 1004
ERROR_CLOSE_RSV1 = 1005
ERROR_CLOSE_RSV2 = 1006
ERROR_BAD_DATA = 1007
ERROR_BAD_MSG = 1008
ERROR_TOO_BIG = 1009
ERROR_SERVER_EXT_FAIL = 1010
ERROR_SERVER_ERR_UNEXPEC = 1011
ERROR_TLS_HANDSHAKE = 1015


"""WebSocket Opcodes"""
OP_CONT = 0x0  # denotes a continuation frame
OP_TEXT = 0x1  # denotes a text frame
OP_BIN = 0x2  # denotes a binary frame
OP_RSV_NC1 = 0x3  # are reserved for further non-control frames
OP_RSV_NC2 = 0x4  # are reserved for further non-control frames
OP_RSV_NC3 = 0x5  # are reserved for further non-control frames
OP_RSV_NC4 = 0x6  # are reserved for further non-control frames
OP_RSV_NC5 = 0x7  # are reserved for further non-control frames
OP_CLOSE = 0x8  # denotes a connection close
OP_PING = 0x9  # denotes a ping
OP_PONG = 0xA  # denotes a pong
OP_RSV_CTL1 = 0xB  # are reserved for further control frames
OP_RSV_CTL2 = 0xC  # are reserved for further control frames
OP_RSV_CTL3 = 0xD  # are reserved for further control frames
OP_RSV_CTL4 = 0xE  # are reserved for further control frames
OP_RSV_CTL5 = 0xF  # are reserved for further control frames


class ParamDict(dict):
    """Dict subclass that allows self-referencing during init
       From: http://stackoverflow.com/a/15988902"""
    def __getitem__(self, key):
        val = dict.__getitem__(self, key)
        return val(self) if callable(val) else val


def bytes2bitlist(data):
    """Bytes/ByteArray to bit field list"""
    return [1 if data[i//8] & 1 << (7-i) % 8 else 0 for i in range(len(data)*8)]


def bitlist2bytes(bitlist, byteorder="little"):
    """Bit field list to Bytes/ByteArray """
    if byteorder in ["big", "network"]:  # Byte swap the generated int <- bits
        return bytearray([int("".join(["%d" % j for j in bitlist[i:i + 8]]), 2)
                          for i in range(len(bitlist)-1, -1, -1) if i % 8 == 0])
    else:
        return bytearray([int("".join(["%d" % j for j in bitlist[i:i + 8]]), 2)
                          for i in range(len(bitlist)) if i % 8 == 0])


def bitlist2int(bits, byteorder="little"):
    """Convert bit field list to an integer"""
    if byteorder in ["big", "network"]:  # Byte swap the generated int <- bits
        return int(''.join(["%d" % j for i in range(len(bits)-1, -1, -1)
                            if (i+1) % 8 == 0
                            for j in bits[i:i-8 if i-8 > 0 else None:-1]]), 2)
    else:
        return int(''.join(["%d" % i for i in bits]), 2)


def masking(has_mask, key, payload, payload_len):
    """Mask/Unmask WebSocket payload data"""
    payload = (payload.to_bytes(payload_len, byteorder="big")
               if isinstance(payload, int) else payload)
    if has_mask:
        key = key.to_bytes(4, byteorder="big")
        unmasked_data = [payload[i] ^ key[i % 4] for i in range(len(payload))]
        return bytearray(unmasked_data)
    return payload


def test_bits(data, bits, offset):
    """Test bits in an int
       Python's expanding & shrinking ints truncates the most significant bits
       if they are zero, so we calculate what may be missing before testing."""
    bit_len = data.bit_length() + (bits - data.bit_length())
    if isinstance(offset, range):
        offset_start = bit_len - offset.start
        offset = bit_len - offset.stop
        mask = ((1 << (offset_start - offset)) - 1) << offset
    else:
        offset = (bit_len - 1) - offset
        mask = 1 << offset
    return (data & mask) >> offset


class TinyWS:
    WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, client, addr):
        self.client = client
        self.addr = addr


    def start(self):
        self.handshake()
        self.processing()


    def construct_frame(self, fin=1, payload=b'', opcode=OP_TEXT,
                        mask=0x0, key=None):
        """Construct a new frame with provided data parts"""
        frame = ParamDict(
            {'fin': fin,
             'rsv1': 0x0,
             'rsv2': 0x0,
             'rsv3': 0x0,
             'opcode': int(opcode),
             'mask': mask,
             'masking_key': key.to_bytes(4, byteorder="big") if key else None,
             'payload_data': masking(mask, key, payload, len(payload)),
             'payload_len': (len(payload) if len(payload) <= 125 else
                             126 if 126 <= len(payload) <= 65535 else
                             127),
             'ext_payload_len': (len(payload) if len(payload) >= 125 else 0)})
        return frame


    def parse_frame(self, data_bytes, get_payload_len=False):
        """Parse raw frame bytes, retrieve frame fields, and returns a frame"""
        data = int.from_bytes(data_bytes, byteorder="big")
        bits = len(data_bytes) * 8
        frame = ParamDict(
            {'fin': test_bits(data, bits, 0),
             'rsv1': test_bits(data, bits, 1),
             'rsv2': test_bits(data, bits, 2),
             'rsv3': test_bits(data, bits, 3),
             'opcode': test_bits(data, bits, range(4, 8)),
             'mask': test_bits(data, bits, 8),
             'payload_len': test_bits(data, bits, range(9, 16)),
             'ext_payload_len': lambda self: (
                 test_bits(data, bits, range(16, 32)) if self['payload_len'] == 126 else
                 test_bits(data, bits, range(16, 80)) if self['payload_len'] == 127 else
                 0),  # len <= 125
             'masking_key': lambda self: (
                 0 if not self['mask'] else
                 test_bits(data, bits, range(16, 48)) if self['payload_len'] <= 125 else
                 test_bits(data, bits, range(32, 64)) if self['payload_len'] == 126 else
                 test_bits(data, bits, range(80, 112))),  # len == 127
             'ext_payload_off': lambda self: (
                 32 if self['payload_len'] == 126 else
                 80 if self['payload_len'] == 127 else
                 16),  # len <= 125
             'masking_key_off': lambda self: (self['ext_payload_off'] +
                                              (32 * self['mask'])),
             'payload_data_off': lambda self: self['masking_key_off'],
             'payload_data': lambda self: (
                 b'' if get_payload_len else
                 masking(self['mask'], self['masking_key'],
                         test_bits(data, bits,
                                   range(self['payload_data_off'],
                                         self['payload_data_off'] +
                                         self['payload_len']*8)),
                         self['payload_len']) if self['payload_len'] <= 125 else
                 masking(self['mask'], self['masking_key'],
                         test_bits(data, bits,
                                   range(self['payload_data_off'],
                                         self['payload_data_off'] +
                                         self['ext_payload_len']*8)),
                         self['ext_payload_len'])),
             'frame_len': lambda self: (
                 self['payload_data_off']//8 + self['payload_len']
                 if self['payload_len'] <= 125 else
                 self['payload_data_off']//8 + self['ext_payload_len'])
            })

        return frame


    def assemble_raw_frame(self, frame):
        """Take dict-like frame and bit-pack into bytes"""
        payload_data = frame['payload_data']
        payload_len = frame['payload_len']
        ex_payload_len = frame['ext_payload_len']
        masking_key = (frame['masking_key'].to_bytes(4, byteorder="big")
                       if frame['mask'] else [])

        raw_frame = [frame['fin'], frame['rsv1'], frame['rsv2'], frame['rsv3']]
        raw_frame += bytes2bitlist(bytes([frame['opcode']]))[4:]
        raw_frame += [0]  # [frame['mask']]

        raw_frame += bytes2bitlist(bytes([payload_len]))[1:]  # 7 bits for len
        if payload_len == 126:
            raw_frame += bytes2bitlist(ex_payload_len.to_bytes(2, byteorder="big"))
        elif payload_len == 127:
            raw_frame += bytes2bitlist(ex_payload_len.to_bytes(8, byteorder="big"))

        #raw_frame += bytes2bitlist(masking_key)
        raw_frame += bytes2bitlist(payload_data)

        return bitlist2bytes(raw_frame)


    def recv_data(self, length=2):
        """Read data from socket"""
        #dec = codecs.getincrementaldecoder('utf8')()
        partial_frame = None

        def _recv(length):
            _data = bytes()
            while len(_data) != length:
                try:
                    #if partial_frame:
                    #    dec.decode(_data)
                    _data += self.client.recv(length)
                except socket.timeout:
                    break
                #except UnicodeDecodeError as e:
                #    frame_close(client, ERROR_BAD_DATA, str(e))
                #    break
            return _data

        f_len = 0
        data = _recv(length)
        p_len = data[1] & 0b01111111

        while True:
            if p_len <= 125:
                partial_frame = self.parse_frame(data, get_payload_len=True)
                f_len = partial_frame['frame_len']
                length = f_len - len(data)
                if len(data) == f_len:
                    return self.parse_frame(data)
            elif p_len == 126:
                if len(data) == 2:
                    length = 2
                elif len(data) == 4:
                    partial_frame = self.parse_frame(data, get_payload_len=True)
                    f_len = partial_frame['frame_len']
                    length = f_len - len(data)
                elif len(data) == f_len:
                    return self.parse_frame(data)
            elif p_len == 127:
                if len(data) == 2:
                    length = 8
                elif len(data) == 10:
                    partial_frame = self.parse_frame(data, get_payload_len=True)
                    f_len = partial_frame['frame_len']
                    length = f_len - len(data)
                elif len(data) == f_len:
                    return self.parse_frame(data)

            data += _recv(length)


    def send_data(self, frames):
        raw_frame = bytearray()
        if isinstance(frames, list):
            for frame in [f for f in frames if f]:
                raw_frame += self.assemble_raw_frame(frame)
        elif frames:
            raw_frame = self.assemble_raw_frame(frames)
        else:
            return

        total_sent = 0
        while total_sent < len(raw_frame):
            sent = self.client.send(raw_frame[total_sent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total_sent += sent

        return total_sent


    def parse_headers(self, data):
        headers = {}
        lines = data.splitlines()
        for line in lines:
            parts = line.split(": ", 1)
            if len(parts) == 2:
                headers[parts[0]] = parts[1]
        headers['code'] = lines[len(lines) - 1]
        return headers


    def handshake(self):
        data = self.client.recv(1024).decode('utf-8')
        headers = self.parse_headers(data)
        key = headers['Sec-WebSocket-Key']
        key = b64encode(hashlib.sha1((key +
                                      self.WS_GUID).encode('utf-8')).digest())
        shake = "HTTP/1.1 101 Switching Protocols\r\n"
        shake += "Server: AutobahnTestSuite/0.7.5-0.10.9\r\n"
        shake += "Upgrade: websocket\r\n"
        shake += "Connection: Upgrade\r\n"
        shake += "Sec-WebSocket-Location: ws://{0}/\r\n".format(headers['Host'])
        #shake += "Sec-WebSocket-Protocol: graphics\r\n"
        shake += "Sec-WebSocket-Accept: {0}\r\n".format(key.decode('utf-8'))
        shake += "Sec-WebSocket-Version: 13\r\n\r\n"
        return self.client.send(shake.encode('UTF-8'))


    def frame_close(self, code, msg):
        payload_data = code.to_bytes(2, byteorder="big") + str.encode(msg)
        frame = self.construct_frame(fin=1, payload=payload_data,
                                     opcode=OP_CLOSE)
        return frame


    def frame_text(self, msg):
        payload_data = str.encode(msg) if isinstance(msg, str) else msg
        frame = self.construct_frame(fin=1, payload=payload_data,
                                     opcode=OP_TEXT)
        return frame


    def frame_bin(self, msg):
        payload_data = str.encode(msg) if isinstance(msg, str) else msg
        frame = self.construct_frame(fin=1, payload=payload_data,
                                     opcode=OP_BIN)
        return frame


    def frame_ping(self, data):
        return (self.construct_frame(fin=1, payload=data,
                                     opcode=OP_PING)
                if len(data) <= 125 else None)


    def frame_pong(self, data):
        return (self.construct_frame(fin=1, payload=data,
                                     opcode=OP_PONG)
                if len(data) <= 125 else None)


    def frame_close(self, code=ERROR_NONE, msg=""):
        payload_data = code.to_bytes(2, byteorder="big") + str.encode(msg)
        frame = self.construct_frame(fin=1, payload=payload_data,
                                     opcode=OP_CLOSE)
        return frame


    def process_close(self, frame):
        self.send_data(frame)
        self.client.close()


    def process_text(self, frame):
        pass


    def process_binary(self, frame):
        pass


    def process_ping(self, frame):
        pass


    def closing(self, code=ERROR_NONE, msg=""):
        frame = self.frame_close(code, msg)
        self.process_close(frame)


    def processing(self):
        """Basic Frame Processing Logic"""
        pinged = False
        frag_payload = None
        frag_opcode = None
        dec = codecs.getincrementaldecoder('utf8')()
        frame = None

        while True:
            try:
                frame = self.recv_data() if not frame else frame
            except ConnectionResetError:
                break

            if ((not frame['fin'] and frame['opcode'] >= OP_CLOSE) or
                    (OP_CONT < frame['opcode'] < OP_CLOSE and 
                     (frag_opcode or (frag_opcode and frame['fin']))) or
                    (frame['rsv1'] or frame['rsv2'] or frame['rsv3'])):
                self.closing(ERROR_PROTO, "Proto Error")
                return
            elif (OP_CONT < frame['opcode'] < OP_CLOSE) and not frame['fin']:
                frag_opcode = frame['opcode']
                frag_payload = frame['payload_data']
                if frag_opcode == 1:
                    try:
                        dec.decode(frame['payload_data'])
                    except UnicodeDecodeError as err:
                        self.closing(ERROR_BAD_DATA, str(err))
                        return
            elif frame['opcode'] == OP_CONT:
                if not frag_opcode:
                    self.closing(ERROR_PROTO, "Proto Error")
                    return
                frag_payload += frame['payload_data']
                if frag_opcode == 1:
                    try:
                        dec.decode(frame['payload_data'])
                    except UnicodeDecodeError as err:
                        self.closing(ERROR_BAD_DATA, str(err))
                        return
                if frame['fin']:
                    frame = self.construct_frame(frame['fin'], frag_payload,
                                                 frag_opcode)
                    frag_payload = None
                    frag_opcode = None
                    continue  # Process the assembled continued frame normally.
            elif frame['opcode'] == OP_TEXT:
                try:
                    dec.decode(frame['payload_data'])
                    self.process_text(frame)
                except UnicodeDecodeError as err:
                    self.closing(ERROR_BAD_DATA, str(err))
                    return
            elif frame['opcode'] == OP_BIN:
                self.process_binary(frame)
            elif OP_RSV_NC1 <= frame['opcode'] <= OP_RSV_NC5:
                self.closing(ERROR_PROTO, "Proto Error")
                return
            elif frame['opcode'] == OP_CLOSE:
                self.closing(ERROR_NONE, "No Error")
                return
            elif frame['opcode'] == OP_PING:
                pong_frame = self.frame_pong(frame['payload_data'])
                if pong_frame:
                    self.send_data(pong_frame)
                else:
                    self.closing(ERROR_PROTO, "Proto Error")
                    return
            elif frame['opcode'] == OP_PONG:
                if pinged:
                    pinged = False
            elif OP_RSV_CTL1 <= frame['opcode'] <= OP_RSV_CTL5:
                self.closing(ERROR_PROTO, "Proto Error")
                return

            frame = None


def start_ws_server(ws_cls=TinyWS):
    if not issubclass(ws_cls, TinyWS):
        print("Required is the TinyWS class, or subclass.")
        return
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', PORT))
    s.listen(5)
    print(f"Listening on port TCP {PORT} using class {ws_cls}")
    while True:
        conn, addr = s.accept()
        print('Connection from:', addr)
        clients.append(conn)
        ws = ws_cls(conn, addr)
        threading.Thread(target=ws.start(), args=(conn, addr)).start()
