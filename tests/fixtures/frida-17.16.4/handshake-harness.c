#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "loader.c"

static int scenario, receives, entry_calls, closed_library;
static unsigned seen[256];
ssize_t frida_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d) { return 123; }
static int fake_close (int fd) { return 0; }
static int fake_detach (pthread_t thread) { return 0; }
static int fake_fcntl (int fd, int cmd, ...) { return 0; }
static ssize_t fake_send (int fd, const void * data, size_t len, int flags) {
  if ((flags & MSG_DONTWAIT) != 0) {
    assert (len == 1);
    if (scenario == 4) return -1;
  }
  if (len == 1) seen[*(const unsigned char *) data]++;
  return len;
}
static ssize_t fake_recv (int fd, struct msghdr * msg, int flags) {
  receives++;
  if (receives == 1 && scenario == 1) return -1;
  if (receives == 1 && scenario == 5) return 0;
  if (receives == 1 && scenario == 6) { msg->msg_controllen = 0; return 1; }
  if (msg->msg_control != NULL) {
    struct cmsghdr * c = msg->msg_control;
    c->cmsg_len = CMSG_LEN (sizeof (int));
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    *(int *) CMSG_DATA (c) = 42;
  } else {
    *(unsigned char *) msg->msg_iov[0].iov_base = FRIDA_MESSAGE_ACK;
  }
  return 1;
}
static void entry (const char * data, int * policy, void * state) { entry_calls++; }
static void * fake_dlopen (const char * path, int flags, const void * caller) {
  return scenario == 2 ? NULL : (void *) 1;
}
static void * fake_dlsym (void * handle, const char * symbol, const void * caller) {
  return scenario == 3 ? NULL : (void *) entry;
}
static int fake_dlclose (void * handle) { closed_library++; return 0; }
int main (int argc, char ** argv) {
  scenario = atoi (argv[1]);
  FridaLibcApi api = { .send = fake_send, .recvmsg = fake_recv, .close = fake_close,
    .pthread_detach = fake_detach, .fcntl = fake_fcntl, .sprintf = sprintf,
    .dlopen = fake_dlopen, .dlsym = fake_dlsym, .dlclose = fake_dlclose };
  FridaLoaderContext ctx = { .ctrlfds = { -1, 10 }, .libc = &api };
  frida_main (&ctx);
  assert (entry_calls == ((scenario == 0 || scenario == 4) ? 1 : 0));
  assert (closed_library == ((scenario == 0 || scenario == 3 || scenario == 4) ? 1 : 0));
  assert (seen[FRIDA_MESSAGE_HELLO] == 1 && seen[FRIDA_MESSAGE_BYE] == 1);
  assert (seen[FRIDA_MESSAGE_READY] == ((scenario == 0 || scenario == 4) ? 1 : 0));
  if (scenario != 4) assert (seen[FRIDA_MESSAGE_DIAG_CLEANUP] == 1);
  if (scenario == 0) assert (seen[FRIDA_MESSAGE_DIAG_ENTRY_RETURN] == 1);
  if (scenario == 1) assert (seen[FRIDA_MESSAGE_DIAG_CODE_FD_FAILED] == 1);
  if (scenario == 1) assert (seen[FRIDA_MESSAGE_DIAG_RECV_FD_ERROR] == 1);
  if (scenario == 5) assert (seen[FRIDA_MESSAGE_DIAG_RECV_FD_EOF] == 1);
  if (scenario == 6) assert (seen[FRIDA_MESSAGE_DIAG_RECV_FD_NO_CONTROL] == 1);
  if (scenario == 2) assert (seen[FRIDA_MESSAGE_ERROR_DLOPEN] == 1);
  if (scenario == 3) assert (seen[FRIDA_MESSAGE_ERROR_DLSYM] == 1);
  return 0;
}
