import socket

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverHost = "127.0.0.1"
serverPort = 50000

try: 
    clientSocket.connect((serverHost, serverPort))
    print("Welcome to the Course Information Server.\n")

    while True:
        print ("Press 1 to ask continue, press 2 to quit")
        choice = int(input("Enter your choice: "))
        clientSocket.send(str(choice).encode('utf-8'))

        #somehow the server is not receiving the choice
        
        if choice == 1:
            #send hello to the server
            clientSocket.send("hello".encode('utf-8'))
        
        elif choice == 2:
            byeMessage = clientSocket.recv(8192).decode('utf-8')
            print(byeMessage)
            clientSocket.close()
            break

        else:
            invalidMessage = clientSocket.recv(8192).decode('utf-8')
            print(invalidMessage)

except Exception as e:
    print(e)
    print("Connection closed")

clientSocket.close()
#send hello to the server

#recieve hello (p, g, h_1) from the server

#pick a beta uniformly at random from the interval {1, p-1}
#compute h_2 = g^beta mod p

#send h_2 to the server

#compute K = h_1^beta

#choose a text msg to send to the server
# compute C = AES.Enc^cbc(msg, K)
# send C to the server

#recieve msg' from the server

#if msg' == msg:
#    print "Success"
#else:
#    print "Failure"

#closes the connection