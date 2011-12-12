/* port forwarding functions for TORQUE */

#include <pbs_config.h>   /* the master config generated by configure */

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

#include "port_forwarding.h"


/* handy utility to handle forwarding socket connections to another host
 * pass in an initialized pfwdsock struct with sockets to listen on, a function
 * pointer to get a new socket for forwarding, and a hostname and port number to
 * pass to the function pointer, and it will do the rest. The caller probably
 * should fork first since this function is an infinite loop and never returns */

/* __attribute__((noreturn)) - how do I do this portably? */

void port_forwarder(

  struct pfwdsock *socks,
  int (*connfunc)(char *, int, char *),
  char            *phost,
  int              pport,
  char            *EMsg)  /* O */

  {
  fd_set rfdset, wfdset, efdset;
  int rc, maxsock = 0;

  struct sockaddr_in from;
  torque_socklen_t fromlen;
  int n, n2, sock;

  fromlen = sizeof(from);

  while (1)
    {
    FD_ZERO(&rfdset);
    FD_ZERO(&wfdset);
    FD_ZERO(&efdset);
    maxsock = 0;

    for (n = 0; n < NUM_SOCKS; n++)
      {
      if (!(socks + n)->active)
        continue;

      if ((socks + n)->listening)
        {
        FD_SET((socks + n)->sock, &rfdset);
        }
      else
        {
        if ((socks + n)->bufavail < BUF_SIZE)
          FD_SET((socks + n)->sock, &rfdset);

        if ((socks + ((socks + n)->peer))->bufavail - (socks + ((socks + n)->peer))->bufwritten > 0)
          FD_SET((socks + n)->sock, &wfdset);

        /*FD_SET((socks+n)->sock,&efdset);*/
        }

      maxsock = (socks + n)->sock > maxsock ? (socks + n)->sock : maxsock;
      }

    maxsock++;

    rc = select(maxsock, &rfdset, &wfdset, &efdset, NULL);

    if ((rc == -1) && (errno == EINTR))
      continue;

    if (rc < 0)
      {
      perror("port forwarding select()");

      exit(EXIT_FAILURE);
      }

    for (n = 0;n < NUM_SOCKS;n++)
      {
      if (!(socks + n)->active)
        continue;

      if (FD_ISSET((socks + n)->sock, &rfdset))
        {
        if ((socks + n)->listening)
          {
          int newsock = 0, peersock = 0;

          if ((sock = accept((socks + n)->sock, (struct sockaddr *) & from, &fromlen)) < 0)
            {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR) || (errno == ECONNABORTED))
              continue;

            close((socks + n)->sock);

            (socks + n)->active = 0;

            continue;
            }

          newsock = peersock = 0;

          for (n2 = 0; n2 < NUM_SOCKS; n2++)
            {
            if ((socks + n2)->active || (((socks + n2)->peer != 0) && (socks + ((socks + n2)->peer))->active))
              continue;

            if (newsock == 0)
              newsock = n2;
            else if (peersock == 0)
              peersock = n2;
            else
              break;
            }

          (socks + newsock)->sock      = (socks + peersock)->remotesock = sock;
          (socks + newsock)->listening = (socks + peersock)->listening = 0;
          (socks + newsock)->active    = (socks + peersock)->active    = 1;
          (socks + newsock)->peer      = (socks + peersock)->sock      = connfunc(phost, pport, EMsg);
          (socks + newsock)->bufwritten = (socks + peersock)->bufwritten = 0;
          (socks + newsock)->bufavail  = (socks + peersock)->bufavail  = 0;
          (socks + newsock)->buff[0]   = (socks + peersock)->buff[0]   = '\0';
          (socks + newsock)->peer      = peersock;
          (socks + peersock)->peer     = newsock;
          }
        else
          {
          /* non-listening socket to be read */

          rc = read(
                 (socks + n)->sock,
                 (socks + n)->buff + (socks + n)->bufavail,
                 BUF_SIZE - (socks + n)->bufavail);

          if (rc < 1)
            {
            shutdown((socks + n)->sock, SHUT_RDWR);
            close((socks + n)->sock);
            (socks + n)->active = 0;
            }
          else
            {
            (socks + n)->bufavail += rc;
            }
          }
        } /* END if rfdset */
      } /* END foreach fd */

    for (n = 0; n < NUM_SOCKS; n++)
      {
      if (!(socks + n)->active)
        continue;

      if (FD_ISSET((socks + n)->sock, &wfdset))
        {
        int peer = (socks + n)->peer;

        rc = write(
               (socks + n)->sock,
               (socks + peer)->buff + (socks + peer)->bufwritten,
               (socks + peer)->bufavail - (socks + peer)->bufwritten);

        if (rc < 1)
          {
          shutdown((socks + n)->sock, SHUT_RDWR);
          close((socks + n)->sock);
          (socks + n)->active = 0;
          }
        else
          {
          (socks + peer)->bufwritten += rc;
          }
        } /* END if wfdset */

      } /* END foreach fd */

    for (n2 = 0; n2 <= 1;n2++)
      {
      for (n = 0; n < NUM_SOCKS; n++)
        {
        int peer;

        if (!(socks + n)->active || (socks + n)->listening)
          continue;

        peer = (socks + n)->peer;

        if ((socks + n)->bufwritten == (socks + n)->bufavail)
          {
          (socks + n)->bufwritten = (socks + n)->bufavail = 0;
          }

        if (!(socks + peer)->active && ((socks + peer)->bufwritten == (socks + peer)->bufavail))
          {
          shutdown((socks + n)->sock, SHUT_RDWR);
          close((socks + n)->sock);

          (socks + n)->active = 0;
          }
        }
      }
    }   /* END while(1) */
  }     /* END port_forwarder() */






/* disable nagle on a socket */

void set_nodelay(

  int fd)

  {
  int opt;
  torque_socklen_t optlen;

  optlen = sizeof(opt);

  if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1)
    {
    fprintf(stderr, "getsockopt TCP_NODELAY: %.100s", strerror(errno));
    return;
    }

  if (opt == 1)
    {
    fprintf(stderr, "fd %d is TCP_NODELAY", fd);
    return;
    }

  opt = 1;

  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1)
    fprintf(stderr, "setsockopt TCP_NODELAY: %.100s", strerror(errno));

  return;
  }




/* return a socket to the specified X11 unix socket */

int connect_local_xsocket(

  u_int dnr)

  {
  int sock;

  struct sockaddr_un addr;

  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
    fprintf(stderr, "socket: %.100s", strerror(errno));
    return -1;
    }

  memset(&addr, 0, sizeof(addr));

  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof addr.sun_path, X_UNIX_PATH, dnr);

  if (connect(sock, (struct sockaddr *) & addr, sizeof(addr)) == 0)
    return sock;

  close(sock);

  fprintf(stderr, "connect %.100s: %.100s", addr.sun_path, strerror(errno));

  return(-1);
  }





int x11_connect_display(

  char *display,
  int   alsounused,
  char *EMsg)        /* O */

  {
#ifndef HAVE_GETADDRINFO
  /* this was added for cygwin which doesn't seem to have a working
   * getaddrinfo() yet.
   * this will have to be figured out later */

  if (EMsg != NULL)
    EMsg[0] = '\0';

  return(-1);

#else

  int display_number, sock = 0;

  char buf[1024], *cp;

  struct addrinfo hints, *ai, *aitop;

  char strport[NI_MAXSERV];

  int gaierr;

  if (EMsg != NULL)
    EMsg[0] = '\0';

  /*
  * Now we decode the value of the DISPLAY variable and make a
  * connection to the real X server.
  */

  /*
  * Check if it is a unix domain socket.  Unix domain displays are in
  * one of the following formats: unix:d[.s], :d[.s], ::d[.s]
  */
  if (strncmp(display, "unix:", 5) == 0 ||
      display[0] == ':')
    {
    /* Connect to the unix domain socket. */
    if (sscanf(strrchr(display, ':') + 1, "%d", &display_number) != 1)
      {
      fprintf(stderr, "Could not parse display number from DISPLAY: %.100s",
              display);
      return -1;
      }

    /* Create a socket. */
    sock = connect_local_xsocket(display_number);

    if (sock < 0)
      return -1;

    /* OK, we now have a connection to the display. */
    return sock;
    }

  /*
  * Connect to an inet socket.  The DISPLAY value is supposedly
  * hostname:d[.s], where hostname may also be numeric IP address.
  */
  snprintf(buf, sizeof(buf), "%s", display);

  cp = strchr(buf, ':');

  if (!cp)
    {
    fprintf(stderr, "Could not find ':' in DISPLAY: %.100s", display);
    return -1;
    }

  *cp = 0;

  /* buf now contains the host name.  But first we parse the display number. */

  if (sscanf(cp + 1, "%d", &display_number) != 1)
    {
    fprintf(stderr, "Could not parse display number from DISPLAY: %.100s",
            display);
    return -1;
    }

  /* Look up the host address */
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;

  hints.ai_socktype = SOCK_STREAM;

  snprintf(strport, sizeof strport, "%d", 6000 + display_number);

  if ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0)
    {
    fprintf(stderr, "%100s: unknown host. (%s)", buf, gai_strerror(gaierr));
    return -1;
    }

  for (ai = aitop; ai; ai = ai->ai_next)
    {
    /* Create a socket. */
    sock = socket(ai->ai_family, SOCK_STREAM, 0);

    if (sock < 0)
      {
      fprintf(stderr, "socket: %.100s", strerror(errno));
      continue;
      }

    /* Connect it to the display. */
    if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0)
      {
      fprintf(stderr, "connect %.100s port %d: %.100s", buf,
              6000 + display_number, strerror(errno));
      close(sock);
      continue;
      }

    /* Success */
    break;
    }

  freeaddrinfo(aitop);

  if (!ai)
    {
    fprintf(stderr, "connect %.100s port %d: %.100s", buf, 6000 + display_number,
            strerror(errno));
    return -1;
    }

  set_nodelay(sock);

  return sock;
#endif /* HAVE_GETADDRINFO */
  }


