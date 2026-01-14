import socket

msg = bytes.fromhex(
    "21310060000000002b9b6c81000a13122b3fc42f7d8c2b854340dcec37d3a9f54db2e478ea640488e629046cc5028385d50173cc57b24ec78bff170d2d54ee60df6dc82d9e0a51c94a442d89ed12b63dcd8632e92657d4d85bdb83e294049664"
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg, ("192.168.31.141", 54321))
s.close()
