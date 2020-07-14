#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define VERSION "snetool 1.0.0"
#define INFO "NAME:\n  snetool - simple network tool\n\nDESCRIPTION:\n  snetool provides basic functionality such as:\n  - letting you know your local ip\n  - pinging to hosts in the same network (need to run with admin privileges)\n  - scanning hosts searching for open ports\n  \nEXAMPLES:\n  snetool -i                          # get local ip\n  sudo snetool -p 192.168.1.1 2       # ping to 192.168.1.1 with 2s timeout\n  snetool -s -s google.com 75 85 500  # scan google.com from port 75 to 85 with\n  500 ms timeout\n\nVERSION:\n  snetool 1.0.0\n\nAUTHOR:\n  Mariano Dato - <marianodato@gmail.com>\n\nUSAGE:\n  snetool <command>\n\nCOMMANDS:\n  -h, Show help text and quit\n  -i, Show local ip and quit\n  -p <host> <timeout[s]>, Ping host and quit\n  -s <host> <start-port-number> <end-port-number> <timeout[ms]>, Scan host ports\n  from start-port-number to end-port-number and quit\n  -v, Show version number and quit"
#define INVALID_USAGE "snetool: try 'snetool -h' for more information"
#define DEFDATALEN 56
#define MAXIPLEN 60
#define MAXICMPLEN 76

extern int optind;
char *hostname = NULL;

int getLocalIp(char *);
int ping(char *, int);
int checksum(unsigned short *, int);
void noResponse(int);
int portScan(char *, int, int, int);

int main(int argc , char **argv){
    int opt = 0;
    int ret = 0;
    int timeout = 0;
    char buffer[100];
    int end_port = 0;
    int start_port = 0;

    memset(buffer,0,sizeof(buffer));

    if (argc<2 || argc>6){
        printf("%s\n", INVALID_USAGE);
        exit(EXIT_FAILURE);
    }    

    while ((opt = getopt(argc, argv, "hip:s:v")) != -1) {
        switch (opt) {
            
            case 'h':
                if(argc != 2){
                    printf("%s\n", INVALID_USAGE);
                    exit(EXIT_FAILURE);
                }

                printf("%s\n", INFO);
                exit(EXIT_SUCCESS);

            case 'i':
                if(argc != 2){
                    printf("%s\n", INVALID_USAGE);
                    exit(EXIT_FAILURE);
                }

                ret = getLocalIp(buffer);

                if (ret == EXIT_SUCCESS){
                    printf("%s\n" , buffer);
                    exit(EXIT_SUCCESS);
                }else{
                    exit(EXIT_FAILURE);
                }

            case 'p':
                if(argc != 4){
                    printf("%s\n", INVALID_USAGE);
                    exit(EXIT_FAILURE);
                }

                hostname = argv[2];
                timeout = atoi(argv[3]);

                if (timeout == 0){
                    printf("snetool: invalid timeout argument\n");
                    exit(EXIT_FAILURE);
                }
                
                ret = ping(hostname, timeout);

                if (ret == EXIT_SUCCESS){
                    exit(EXIT_SUCCESS);
                }else{
                    exit(EXIT_FAILURE);
                }

            case 's':
                if(argc != 6){
                    printf("%s\n", INVALID_USAGE);
                    exit(EXIT_FAILURE);
                }

                hostname = argv[2];
                start_port = atoi(argv[3]);
                end_port = atoi(argv[4]);
                timeout = atoi(argv[5]);

                if (end_port == 0){
                    printf("snetool: invalid end-port-number argument\n");
                    exit(EXIT_FAILURE);
                }

                if (timeout == 0){
                    printf("snetool: invalid timeout argument\n");
                    exit(EXIT_FAILURE);
                }

                if (start_port > end_port){
                    printf("snetool: start-port-number cannot be bigger than end-port-number\n");
                    exit(EXIT_FAILURE);
                }

                ret = portScan(hostname, start_port, end_port, timeout);

                if (ret == EXIT_SUCCESS){
                    exit(EXIT_SUCCESS);
                }else{
                    exit(EXIT_FAILURE);
                }

            case 'v':
                if(argc != 2){
                    printf("%s\n", INVALID_USAGE);
                    exit(EXIT_FAILURE);
                }

                printf("%s\n", VERSION);
                exit(EXIT_SUCCESS);

            default:
                printf("%s\n", INVALID_USAGE);
                exit(EXIT_FAILURE);
        }
    }
}

int getLocalIp(char * buffer){
    const char* kGoogleDnsIp = "8.8.8.8";
    struct sockaddr_in serv;
    struct sockaddr_in name;
    int dns_port = 53;
    socklen_t namelen;
    const char *p = NULL;
    int sock = 0;
    int err = 0;

    sock = socket( AF_INET, SOCK_DGRAM, 0);

    if(sock < 0){
        printf("snetool: cannot create socket\n");
        return EXIT_FAILURE;
    }
 
    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );
 
    err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
 
    namelen = sizeof(name);
    
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
 
    p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    if(p == NULL){
        printf("snetool: cannot get local ip\n");
        return EXIT_FAILURE;
    }
 
    close(sock);

    return EXIT_SUCCESS;
}

int ping(char *hostname, int timeout){
    struct hostent *h;
    struct sockaddr_in pingaddr;
    struct icmp *pkt;
    int pingsock = 0;
    int c = 0;
    char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
    struct sockaddr_in from;
    socklen_t fromlen;
    struct ip *iphdr;

    if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {
        printf("snetool: cannot create socket\n");
        printf("snetool: make sure you are running this command with admin privileges\n");
        return EXIT_FAILURE;
    }

    setuid(getuid());

    memset(&pingaddr, 0, sizeof(struct sockaddr_in));

    pingaddr.sin_family = AF_INET;

    if (!(h = gethostbyname(hostname))) {
        printf("snetool: unknown host %s\n", hostname);
        return EXIT_FAILURE;
    }

    memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
    hostname = h->h_name;

    pkt = (struct icmp *) packet;
    memset(pkt, 0, sizeof(packet));
    pkt->icmp_type = ICMP_ECHO;
    pkt->icmp_cksum = checksum((unsigned short *) pkt, sizeof(packet));

    c = sendto(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));

    if (c < 0 || c != sizeof(packet)) {
        printf("snetool: write incomplete\n");
        return EXIT_FAILURE;
    }

    signal(SIGALRM, noResponse);

    alarm(timeout);

    while (1) {
        fromlen = sizeof(from);

        if ((c = recvfrom(pingsock, packet, sizeof(packet), 0, (struct sockaddr *) &from, &fromlen)) < 0) {
            continue;
        }

        if (c >= 76) {
            iphdr = (struct ip *) packet;
            pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2));
            if (pkt->icmp_type == ICMP_ECHOREPLY){
                break;
            }
        }   
    }

    printf("%s is alive\n", hostname);
    return EXIT_SUCCESS;
}

int checksum(unsigned short *buf, int sz){
    int nleft = sz;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short ans = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&ans) = *(unsigned char *) w;
        sum += ans;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    ans = ~sum;
    return (ans);   
}

void noResponse(int ign){
    printf("%s is unreachable\n", hostname);
    exit(EXIT_FAILURE);
}

int portScan(char * hostname, int start, int end, int timeout){
    int i = 0;
    int sock = 0;
    fd_set fdset;
    int so_error = 0;
    struct timeval tv;
    struct hostent *host;
    struct sockaddr_in sa;
    
    strncpy((char*)&sa , "" , sizeof sa);
    sa.sin_family = AF_INET;

    if(isdigit(hostname[0])){
        sa.sin_addr.s_addr = inet_addr(hostname);
    }else if((host = gethostbyname(hostname)) != 0){
        strncpy((char*)&sa.sin_addr , (char*)host->h_addr , sizeof sa.sin_addr);
    }else{
        printf("snetool: unknown host %s\n", hostname);
        return EXIT_FAILURE;
    }
    
    for( i = start ; i <= end ; i++) {
        sa.sin_port = htons(i);
        sock = socket(AF_INET , SOCK_STREAM , 0);
        
        if(sock < 0) {
            printf("snetool: cannot create socket\n");
            return EXIT_FAILURE;
        }

        fcntl(sock, F_SETFL, O_NONBLOCK);

        connect(sock , (struct sockaddr*)&sa , sizeof sa);
         
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 0;
        tv.tv_usec = timeout*1000;

        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1){
            socklen_t len = sizeof so_error;

            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

            if (so_error == 0) {
                printf("%d is open\n",  i);
            }
        }else{
            printf("%d is closed\n",  i);
        }

        close(sock);
    }
    
    return EXIT_SUCCESS;
}
