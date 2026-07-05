import socket, struct
s=socket.create_connection(("127.0.0.1",5502))          # modbus decoy
s.sendall(struct.pack(">HHHB",1,0,6,1)+struct.pack(">BHH",5,0,0xFF00))  # write coil
print(s.recv(64)); s.close()