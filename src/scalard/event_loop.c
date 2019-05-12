#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <sys/epoll.h>

#include "event_loop.h"

#include "socket.h"

int epfd;

void event_loop_init() {
  if ((epfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
    err(EXIT_FAILURE, "epoll_create1");
}

int event_loop_register(struct event_loop_handlers **ptr) {
  struct event_loop_handlers *h = *ptr;
  struct epoll_event event = { 0 };
  event.data.ptr = ptr;
  if (h->read)
    event.events |= EPOLLIN;
  if (h->close)
    event.events |= EPOLLRDHUP;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, h->fd(ptr), &event) != 0)
    return -1;
  return 0;
}

void event_loop() {
  for (;;) {
    struct epoll_event events[128];
    int n_events;

    if ((n_events = epoll_wait(epfd, events, 128, -1)) < 0) {
      if (errno != EINTR)
        warn("epoll_wait");
      continue;
    }

    for (int i = 0; i < n_events; ++i) {
      struct event_loop_handlers **ptr = events[i].data.ptr, *h = *ptr;
      int close = 0;

      if (h->read && (events[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)))
        close |= h->read(ptr);

      if (events[i].events & EPOLLRDHUP) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, h->fd(ptr), NULL) != 0)
          warn("epoll_ctl");
        else if (h->close)
          h->close(ptr);
      }
    }
  }
}
