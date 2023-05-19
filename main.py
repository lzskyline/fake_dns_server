import socket
import struct

# TODO: 增加通配符支持
hijacked_map = {
    "fakedomain.com": "0.0.0.0"
}
upstream_dns_server = "8.8.8.8"


def parse_dns_request(data):
  domain = ""
  pos = 12
  length = data[pos]
  while length != 0:
    domain_part = data[pos + 1: pos + 1 + length]
    domain += domain_part.decode('utf-8') + "."
    pos += 1 + length
    length = data[pos]
  return domain


def create_dns_response(request, domain):
  ip = hijacked_map[domain].split('.')
  ip_bytes = struct.pack('!BBBB', int(
      ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))

  response = request[:2]
  response += b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
  response += request[12:]
  response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04' + ip_bytes
  return response


def main():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  server_socket.bind(('', 53))

  while True:
    data, addr = server_socket.recvfrom(1024)
    domain = parse_dns_request(data)

    if domain in hijacked_map:
      response = create_dns_response(data, domain)
      server_socket.sendto(response, addr)
    else:
      client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      client_socket.sendto(data, (upstream_dns_server, 53))
      response, _ = client_socket.recvfrom(1024)
      server_socket.sendto(response, addr)


if __name__ == "__main__":
  main()
