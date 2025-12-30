import socket
import threading
import logging
import struct
import select

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SOCKS_VERSION = 0x05
NO_AUTH = 0x00
NO_ACCEPTABLE_METHODS = 0xFF

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Server:
    def __init__(self, host='0.0.0.0', port=1080):
        self.host = host
        self.port = port
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f'SOCKS5 server listening on {self.host}:{self.port}')

        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f'New connection from {client_address[0]}:{client_address[1]}')
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info('Server shutting down...')
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket, client_address):
        try:
            if not self.perform_handshake(client_socket):
                client_socket.close()
                return

            cmd, atyp, dst_addr, dst_port = self.parse_request(client_socket)
            if cmd == CMD_CONNECT:
                self.handle_connect(client_socket, atyp, dst_addr, dst_port)
            else:
                self.send_reply(client_socket, REP_COMMAND_NOT_SUPPORTED)
                client_socket.close()
        except Exception as e:
            logger.error(f'Error handling client {client_address}: {e}')
            try:
                client_socket.close()
            except:
                pass

    def perform_handshake(self, client_socket):
        try:
            data = client_socket.recv(262)
            if len(data) < 3:
                return False

            version, nmethods = struct.unpack('!BB', data[:2])
            if version != SOCKS_VERSION:
                logger.warning(f'Invalid SOCKS version: {version}')
                return False

            methods = list(data[2:2 + nmethods])

            if NO_AUTH in methods:
                client_socket.sendall(struct.pack('!BB', SOCKS_VERSION, NO_AUTH))
                return True
            else:
                client_socket.sendall(struct.pack('!BB', SOCKS_VERSION, NO_ACCEPTABLE_METHODS))
                return False
        except Exception as e:
            logger.error(f'Handshake error: {e}')
            return False

    def parse_request(self, client_socket):
        data = client_socket.recv(262)
        if len(data) < 4:
            raise Exception('Request too short')

        version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])

        if atyp == ATYP_IPV4:
            if len(data) < 10:
                raise Exception('Incomplete IPv4 request')
            dst_addr = socket.inet_ntoa(data[4:8])
            dst_port = struct.unpack('!H', data[8:10])[0]
        elif atyp == ATYP_DOMAIN:
            addr_len = data[4]
            if len(data) < 5 + addr_len + 2:
                raise Exception('Incomplete domain request')
            dst_addr = data[5:5 + addr_len].decode('utf-8')
            dst_port = struct.unpack('!H', data[5 + addr_len:7 + addr_len])[0]
        elif atyp == ATYP_IPV6:
            if len(data) < 22:
                raise Exception('Incomplete IPv6 request')
            dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            dst_port = struct.unpack('!H', data[20:22])[0]
        else:
            self.send_reply(client_socket, REP_ADDRESS_TYPE_NOT_SUPPORTED)
            raise Exception(f'Unsupported address type: {atyp}')

        return cmd, atyp, dst_addr, dst_port

    def handle_connect(self, client_socket, atyp, dst_addr, dst_port):
        try:
            logger.info(f'CONNECT to {dst_addr}:{dst_port}')
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((dst_addr, dst_port))
            remote_socket.setblocking(False)
            client_socket.setblocking(False)

            bind_addr = '0.0.0.0'
            bind_port = remote_socket.getsockname()[1]
            bind_ip = socket.inet_aton(bind_addr)

            reply = struct.pack('!BBBB', SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4)
            reply += bind_ip + struct.pack('!H', bind_port)
            client_socket.sendall(reply)

            logger.info(f'Connected to {dst_addr}:{dst_port}')
            self.relay_data(client_socket, remote_socket)

        except socket.gaierror:
            logger.error(f'DNS resolution failed for {dst_addr}')
            self.send_reply(client_socket, REP_HOST_UNREACHABLE)
            client_socket.close()
        except ConnectionRefusedError:
            logger.error(f'Connection refused by {dst_addr}:{dst_port}')
            self.send_reply(client_socket, REP_CONNECTION_REFUSED)
            client_socket.close()
        except Exception as e:
            logger.error(f'Connection error to {dst_addr}:{dst_port}: {e}')
            self.send_reply(client_socket, REP_GENERAL_FAILURE)
            client_socket.close()

    def send_reply(self, client_socket, rep_code):
        reply = struct.pack('!BBBB', SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4)
        reply += socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
        try:
            client_socket.sendall(reply)
        except:
            pass

    def relay_data(self, client_socket, remote_socket):
        try:
            while True:
                sockets = [client_socket, remote_socket]
                readable, _, _ = select.select(sockets, [], [], 30)

                if not readable:
                    break

                for sock in readable:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return

                        if sock is client_socket:
                            remote_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except BlockingIOError:
                        continue
                    except:
                        return
        except Exception as e:
            logger.debug(f'Relay error: {e}')
        finally:
            try:
                remote_socket.close()
                client_socket.close()
            except:
                pass


def main():
    server = Socks5Server(host='0.0.0.0', port=1080)
    server.start()


if __name__ == '__main__':
    main()