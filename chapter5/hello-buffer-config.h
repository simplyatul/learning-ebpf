#ifndef HELLO_BUFFER_CONFIG_H
#define HELLO_BUFFER_CONFIG_H

struct user_msg_t {
   char message[20];
};

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[20];
   char path[16];
};

#endif
