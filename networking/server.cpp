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

    int sockfd = socket(addr_family, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Error creating socket\n");
        return -1;
    }

    printf("Socket created\n");

    struct sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin6_family = addr_family;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(PROTOCOL_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        printf("Bind failed\n");
        return -1;
    }

    printf("Bind succeeded\n");

    //backlog - max queue size for cons
    if (listen(sockfd, 1) != 0)
    {
        printf("Listen failed\n");
        return -1;
    }

    //printf("Listening on port: %d\n", PROTOCOL_PORT);

    union
    {
        sockaddr_in sin;
        sockaddr_in6 sin6;
    } client_addr;
    int client_addr_size = sizeof(client_addr);

    int connfd = accept(sockfd, (sockaddr *)&client_addr, (socklen_t *)&client_addr_size);
    if (connfd == -1)
    {
        printf("Connection accept failed\n");
        printf("%s | %d\n", strerror(errno), errno);
        return -1;
    }

    char client_addr_string[INET6_ADDRSTRLEN] = {0};
    printf("Client connected! Address is: %s\n",
           inet_ntop(client_addr.sin.sin_family,
                     client_addr.sin.sin_family == AF_INET
                         ? (void *)&client_addr.sin.sin_addr
                         : (void *)&client_addr.sin6.sin6_addr,
                     client_addr_string, sizeof(client_addr_string)));

    if (client_addr.sin.sin_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&client_addr.sin6.sin6_addr))
        printf("Client is v6\n");
    else
        printf("Client is v4\n");

    char in_buf[1024] = {0};
    int bytes_read = recv(connfd, in_buf, sizeof(in_buf), 0);
    printf("%s\n", in_buf);

    char msg[] = "Hi";
    send(connfd, msg, sizeof(msg), 0);

    Handshake hs;

    if (hs.ParseFromFileDescriptor(connfd))
    {
        printf("Parsed successfully\n");

        auto ds_key = hs.ds_keys(0);

        printf(
            "v: %d\nds key size: %d\nds key type: %d\nds key key: %s\n",
            hs.version(),
            hs.ds_keys_size(),
            ds_key.type(),
            ds_key.key().c_str());

        std::string str = "biba ";
        str.insert(std::end(str), std::begin(ds_key.key()), std::end(ds_key.key()));

        printf("size: %d\nlength: %d\n%s\n", str.size(), str.length(), str.c_str());

        char *data = (char *)str.data();
        data[0] = 'a';

        printf("%s\n", str.c_str());
    }
    else
    {
        printf("Parse failed\n");
    }

    return 0;
}