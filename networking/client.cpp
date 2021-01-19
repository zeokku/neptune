#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "../packets/handshake.pb.h"

#define PROTOCOL_PORT 42069

using namespace neptune::packets;

int main()
{
    int addr_family = AF_INET6;
    char addr_str[] = "::1";

    //AF_INET - IPv4, AF_INET6 - v6
    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Error creating socket\n");
        return -1;
    }

    struct sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin6_family = AF_INET6;

    //convert IPv4 and IPv6 addresses from text to binary form
    //server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //1 - ok, 0, -1
    if (inet_pton(addr_family, addr_str, &server_addr.sin6_addr) != 1)
    {
        printf("Invalid address / Address not supported\n");
        return -1;
    }

    //convert values between host and network byte order
    server_addr.sin6_port = htons(PROTOCOL_PORT);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("Connection failed\n");
        return -1;
    }

    printf("Connection established!\n");

    char msg[] = "Hello";
    send(sockfd, msg, sizeof(msg), 0);

    char in_buf[1024] = {0};
    int bytes_read = recv(sockfd, in_buf, sizeof(in_buf), 0);
    printf("%s\n", in_buf);

    Handshake hs;

    hs.set_version(2);

    DS_PublicKey *ds_pub = hs.add_ds_keys();

    ds_pub->set_type(E_DS::ED25519);
    ds_pub->set_key((void *)"boba", 5);

    if (hs.SerializeToFileDescriptor(sockfd))
    {
        printf("Handshake sent!\n");
    }
    else
    {
        printf("Error sending handshake\n");
    }

    return 0;
}