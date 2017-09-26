from tinyws import TinyWS, start_ws_server


class FuzzerServer(TinyWS):
    def process_text(self, frame):
        print("Processing text frame")
        self.send_data(self.frame_text(frame['payload_data']))

    def process_binary(self, frame):
        print("Processing binary frame")
        self.send_data(self.frame_bin(frame['payload_data']))


if __name__ == '__main__':
    start_ws_server(FuzzerServer)
