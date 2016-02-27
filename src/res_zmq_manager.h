/*
 * res_zmq_manager.h
 *
 *  Created on: Feb 19, 2015
 *      Author: pchero
 */

#ifndef SRC_RES_ZMQ_MANAGER_H_
#define SRC_RES_ZMQ_MANAGER_H_

#define DEBUG(fmt, args...) ast_log(AST_LOG_VERBOSE, "[0MQ Manager Debug]: "fmt, args);
#define ERROR(fmt, args...) ast_log(LOG_ERROR, "[0MQ Manager Error]: "fmt, args);
#define MAX_RCV_BUF_LEN 8192

struct unload_string {
    AST_LIST_ENTRY(unload_string) entry;
    struct ast_str* str;
};

struct ast_zmq_pthread_data {
    pthread_t master;
    int accept_fd;
    void *(*fn)(void *);
    const char *name;
};

/**
 @brief global
 */
struct app_
{
    pthread_t       pth_cmd;      //!< cmd process thread.
    struct ast_str* addr_cmd;     //!< cmd socket address
    struct ast_str* addr_evt;     //!< evt socket address

    char* config_name;
    void* zmq_ctx;  //!< zmq context
    void* sock_cmd; //!< zmq command socket.(ZMQ_REP)
    void* sock_evt; //!< zmq event socket.(ZMQ_PUB)

    struct manager_custom_hook* evt_hook;   ///< hook for event
};
extern struct app_* app;


#endif /* SRC_RES_ZMQ_MANAGER_H_ */
