/* Entry point/init */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <signal.h>
#include <sys/stat.h>

#include "child.h"
#include "event_loop.h"
#include "fs_ops.h"
#include "socket.h"

static void daemon_init(void) {
  /* Ignore SIGPIPE because we use pipes for synchronization */
  if (signal(SIGPIPE, SIG_IGN) != 0)
    err(EXIT_FAILURE, "signal(SIGPIPE, SIG_IGN)");
  event_loop_init();
  socket_init();
  fs_ops_init();

  /* We don't want the umask getting in the way */
  umask(0);

  event_loop();
}

int main(int argc, char *argv[]) {
  if (argv[0] && strcmp(argv[0], "__init") == 0)
    child_init(argv);
  else
    daemon_init();
}
