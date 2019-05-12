/* A basic single-threaded epoll-based event loop */

#ifndef SCALAR_EVENT_LOOP_H__
#define SCALAR_EVENT_LOOP_H__

struct event_loop_handlers {
  int (*fd)(void *);
  int (*read)(void *);
  void (*close)(void *);
};

/* Initializes the event loop, exits on error */
void event_loop_init(void);

/* Register fd into the event loop with associated handlers. The handlers will
 * be called with the pointer passed in here; therefore you can use data
 * adjacent to the handler pointer to store addition data for use by your
 * handlers. Returns 0 on success, -1 on error. */
int event_loop_register(struct event_loop_handlers **handlers);

/* Runs the event loop forever */
void event_loop(void);

#endif
