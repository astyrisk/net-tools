#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


int getaddrinfo(const char *node, // ip
                const char *service, // "http" or port number
                const struct addrinfo *hints,
                struct addrinfo **res);


int status;


struct addrinfo hints;
struct addrinfo *servinfo;

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;


status = getaddrinfo("www.example.net", "3490", &hints, &servinfo);
