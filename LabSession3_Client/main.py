import pickle
import socket

# 1. Design a function that as input receives a, b and p, i.e. the parameters given for an elliptic curve
# y^2 = x^3 + ax + b mod p, and two points in this curve P and Q. The output must be R = P + Q

def elliptic_curve_point_addition(a, b, p, P, Q):
    if P == "O":
        return Q
    elif Q == "O":
        return P
    elif P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return "O" # infinito
    else:
        x_p, y_p = P
        x_q, y_q = Q

        # If P = Q
        if x_p == x_q and y_p == y_q:
            m = ((3 * x_p**2 + a) * pow(2 * y_p, p - 2, p)) % p
        else:   # If P != Q
            m = ((y_p - y_q) * pow(x_p - x_q, p - 2, p)) % p

        x_r = (m**2 - x_p - x_q) % p
        y_r = (m * (x_p - x_r) - y_p) % p

        return x_r, y_r


def point_multiplication(a, b, p, P, K):
    Q = P
    temp = P
    for i in range(K-1):
        R = elliptic_curve_point_addition(a, b, p, temp, Q)
        temp = R
    return R


if __name__ == '__main__':
    # defining the curve parameters
    a = 1
    b = 6
    p = 11

    # BASE POINT G
    G = (8, 8)

    # RANDOM INTEGER TO BE THE b
    rb = 7

    # compute public key
    public_key_B = point_multiplication(a, b, p, G, rb)
    print("Bob Public Key: ",public_key_B)
    ##############################################################
    # create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # get the local machine name
    host = socket.gethostname()

    # set port number
    port = 12345

    # connect to the server
    client_socket.connect((host, port))

    #################################################
    #           RECIVING DATA                       #
    # receive data from server
    data = client_socket.recv(1024)

    # Convert the response back into a tuple
    pub_key_A = pickle.loads(data)

    print('Received data from server:', pub_key_A)

    # FOR THE SECRET
    K = point_multiplication(a, b, p, pub_key_A, rb)

    print("K = ", K)

    #################################################
    #           SENDING DATA                        #
    # Convert the tuple to a string representation
    message = pickle.dumps(public_key_B)

    # send data to client
    client_socket.send(message)

    # close the client socket
    client_socket.close()
