#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

void error(const char * msg){
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    if (argc < 2){
        cout << "[-] no port provided" << endl;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) error("[-] can not opening socket");

    bzero((char *)&serv_addr, sizeof(serv_addr));

    portno = atoi(argv[1]);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("[-] on binding");

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    if(newsockfd < 0)
        error("[-] on accept");

    cout << "connected" << endl;

    bzero(buffer, 256);
    n = read(newsockfd, buffer, 255);

    if(n < 0) error("[-] reading from socket");

    cout << "MESSAGE : " << buffer << endl;
    n = write(newsockfd, buffer, sizeof(buffer));

    if(n < 0) error("[-] writing to socket");
    close(newsockfd);
    close(sockfd);

    return 0;
}
