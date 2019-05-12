/* Interacts with clients over the unix domain socket /run/scalar.sock */

#ifndef SCALAR_SOCKET_H__
#define SCALAR_SOCKET_H__

#include "event_loop.h"

/* Initializes the socket, exits on error */
void socket_init(void);

#endif
