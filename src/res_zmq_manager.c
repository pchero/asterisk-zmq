/*!
  \file   res_zmq_manager.c
  \brief

  \author Sungtae Kim
  \date   Aug 22, 2014

 */

#define _GNU_SOURCE

#ifndef AST_MODULE
    #define AST_MODULE "zmq_manager"
#endif

#include <signal.h>
#include <stdbool.h>

#include <zmq.h>
//#include <jansson.h>
#include <unistd.h>

#include <asterisk.h>
#include <asterisk/module.h>
#include <asterisk/cli.h>
#include <asterisk/utils.h>
#include <asterisk/manager.h>
#include <asterisk/config.h>
#include <asterisk/channel.h>
#include <asterisk/ast_version.h>
#include <asterisk/json.h>

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 338557 $")

#define DEBUG(fmt, args...) ast_log(AST_LOG_VERBOSE, "[0MQ Manager Debug]: "fmt, args);
#define ERROR(fmt, args...) ast_log(LOG_ERROR, "[0MQ Manager Error]: "fmt, args);
#define MAX_RCV_BUF_LEN 8192

struct unload_string {
    AST_LIST_ENTRY(unload_string) entry;
    struct ast_str *str;
};

struct ast_zmq_pthread_data {
    pthread_t master;
    int accept_fd;
    void *(*fn)(void *);
    const char *name;
};

typedef struct zmq_data_t_
{
    void* zmq_sock;     //!< zmq socket
    struct ast_json* j_recv;     //!< zmq recv data
} zmq_data_t;

struct app_
{
    pthread_t       pth_cmd;      //!< cmd process thread.
    pthread_t       pth_evt;      //!< evt process thread.
    struct ast_str* addr_cmd;     //!< cmd socket address
    struct ast_str* addr_evt;     //!< evt socket address

    char* config_name;
    void* sock_ctx; //!< zmq context
    void* sock_cmd; //!< zmq command socket.
    void* sock_evt; //!< zmq event socket.
};

static void zmq_cmd_thread(void);
static void trim(char * s);
static void zmq_cmd_handler(void *data);
static int ast_zmq_start(void);
static char* handle_cli_zmq_manager_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static int zmq_evt_helper(int category, const char *event, char *content);
static int line_parse(char* line);


static struct ast_cli_entry cli_zmq_manager_evt[] = {
    AST_CLI_DEFINE(handle_cli_zmq_manager_status, "Shows useful status about zmq manager"),
};


static struct ast_json*  g_json_res = NULL;  //!< action cmd response(array)
static struct ast_json*  g_json_res_tmp = NULL; //!< action cmd response tmp
static struct ast_json*  g_json_evt = NULL;     //!< Event notify

//static ast_mutex_t workers_mutex;
static AST_LIST_HEAD_STATIC(unload_strings, unload_string);

static struct app_ g_app;


/* The helper function is required by struct manager_custom_hook. See __manager_event for details */
static int amihook_helper(int category, const char *event, char *content)
{
    ast_log(LOG_NOTICE, "AMI Event: category[%d], event[%s], content[%s]\n", category, event, content);
    return 0;
}

/* The helper function is required by struct manager_custom_hook. See __manager_event for details */
/**
 *
 * @param category
 * @param event
 * @param content
 * @return
 */
static int zmq_cmd_helper(int category, const char *event, char *content)
{
//    char* key;
//    char* value;

    char* line;
    int   ret;
    char* ptr;
    char* str_tmp;
    bool  flg_send;
//    char* str_resp;


    ast_log(LOG_NOTICE, "AMI Event: category[%d], event[%s], content[%s]\n", category, event, content);

    if(g_json_res_tmp == NULL)
    {
        g_json_res_tmp = ast_json_object_create();
    }

    DEBUG("%s\n", "parsing start..");

    flg_send = false;
    for(str_tmp = content; ; str_tmp = NULL)
    {
        line = strtok_r(str_tmp, "\r\n", &ptr);
        if(line == NULL)
        {
//            ERROR("Could not parse msg. msg[%s]\n", content);
            break;
        }

        DEBUG("Line[%s]\n", line);

        ret = line_parse(line);
        if(ret == false)
        {
            ERROR("Could not parse line. line[%s]\n", line);
            break;
        }
        DEBUG("%s\n", "Line_parse ok");

        // Check last line.
        ret = strcmp(ptr, "\n\r\n");
        if(ret == 0)
        {
            DEBUG("%s\n", "message end");
            flg_send = true;
            break;
        }
    }
    DEBUG("%s\n", "parsing ends..");


    if(flg_send == true)
    {
        DEBUG("send flag on. flag[%d]\n", flg_send);
        ret = ast_json_array_append(g_json_res, g_json_res_tmp);
        ast_json_unref(g_json_res_tmp);
        g_json_res_tmp = NULL;
        if(ret == -1)
        {
            ERROR("Could not append json. ret[%d]\n", ret);
            return 0;
        }
    }

    return 0;
}

/**
 *
 * @param line
 * @return
 */
static int line_parse(char* line)
{
    char* key;
    char* value;

    key = strtok(line, ":");
    value = strtok(NULL, "\r\n");
    if(key == NULL)
    {
        return false;
    }

    ast_json_object_set(g_json_res_tmp, key, ast_json_string_create(value));

    return true;
}

/**
 *
 * @param cfg
 * @param category
 * @param variable
 * @param field
 * @param def
 * @return
 */
static int load_config_string(struct ast_config *cfg, const char *category, const char *variable, struct ast_str **field, const char *def)
{
    struct unload_string *us;
    const char *tmp;

    if (!(us = ast_calloc(1, sizeof(*us))))
    {
        return -1;
    }

    if (!(*field = ast_str_create(16))) {
        ast_free(us);
        return -1;
    }

    tmp = ast_variable_retrieve(cfg, category, variable);

    ast_str_set(field, 0, "%s", tmp ? tmp : def);

    us->str = *field;

    AST_LIST_LOCK(&unload_strings);
    AST_LIST_INSERT_HEAD(&unload_strings, us, entry);
    AST_LIST_UNLOCK(&unload_strings);

    return 0;
}

/**
 * Convert string type message to json type.
 * @param msg
 * @return Success:json_t*, Fail:NULL
 */
static struct ast_json* recv_parse(char* msg)
{
    struct ast_json* j_out;
    struct ast_json_error error;

    j_out = ast_json_load_buf(msg, strlen(msg), &error);
    if(j_out == NULL)
    {
        DEBUG("Could not convert json. msg[%s]\n", msg);
        return NULL;
    }
    return j_out;
}

/**
 * Command recv & response.
 *
 * Binds to the connection_string and waits for new messages.
 */
static void zmq_cmd_thread(void)
{
    char buffer[MAX_RCV_BUF_LEN];
    zmq_data_t* zmq_data;
    int size;
    int ret;
    int64_t opt;
    size_t opt_size;

    while(1)
    {
        opt_size = sizeof(opt);

        ret = zmq_getsockopt(g_app.sock_cmd, ZMQ_EVENTS, &opt, &opt_size);
        if(ret == -1)
        {
            ERROR("Could not recv message. Err[%d]\n", ret);
            continue;
        }
        if((opt & ZMQ_POLLIN) < 1)
        {
            usleep(100);    // just let's break
            continue;
        }

        DEBUG("ret[%d], opt[%ld]\n", ret, opt);
        DEBUG("Recv thread. sock[%p], buffer[%p]\n", g_app.sock_cmd, buffer);

        memset(buffer, 0x00, sizeof(buffer));
        // todo: need to find out. why die... -_-;;;
        size = zmq_recv(g_app.sock_cmd, buffer, MAX_RCV_BUF_LEN - 1, 0);
        DEBUG("Recv cmd. size[%d]\n", size);
        if(size == -1)
        {
            ERROR("Could not get the cmd. err[%d:%s]\n", errno, strerror(errno));
            continue;
        }
        else if(size >= (MAX_RCV_BUF_LEN -1))
        {
            DEBUG("Size over. size[%d]\n", size);
            size = MAX_RCV_BUF_LEN - 1;
        }

        DEBUG("%s", "bug spot...\n");

        buffer[size] = 0;
        DEBUG("Recv cmd. msg[%s]\n", buffer);

        zmq_data = calloc(1, sizeof(zmq_data_t));
        zmq_data->zmq_sock = g_app.sock_cmd;

        zmq_data->j_recv = recv_parse(buffer);
        if(zmq_data->j_recv == NULL)
        {
            ERROR("Could not parse msg. msg[%s]\n", buffer);
            zmq_send(zmq_data->zmq_sock, "Could not parse msg.", strlen("Could not parse msg."), 0);
            continue;
        }
        zmq_cmd_handler(zmq_data);
        ast_json_free(zmq_data->j_recv);
        free(zmq_data);
    }
}

static struct manager_custom_hook test_hook = {
    .file = __FILE__,
    .helper = &amihook_helper,
};

/*
 * CLI command handler.
 *
 * Shows whether the socket is binded or not and the number of calls made so far.
 */
static char* handle_cli_zmq_manager_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
    switch (cmd) {
        case CLI_INIT:
        {
            e->command = "zmq manager status";
            e->usage =
                    "Usage: zmq manager status\n"
                    "       Shows useful stats about zmq manager usage\n";
            return NULL;
        }
        break;

        case CLI_GENERATE:
        {
            return NULL;
        }
        break;
    }

    if (a->argc != 3)
    {
        return CLI_SHOWUSAGE;
    }

    ast_cli(a->fd, "[cmd address: %s]\n", ast_str_buffer(g_app.addr_cmd));
    ast_cli(a->fd, "[evt address: %s]\n", ast_str_buffer(g_app.addr_evt));


    return CLI_SUCCESS;
}


static int unload_module(void)
{
    ast_manager_unregister_hook(&test_hook);
    return ast_cli_unregister_multiple(cli_zmq_manager_evt, ARRAY_LEN(cli_zmq_manager_evt));
}

/**
 *
 * @return
 */
static int _load_module(void)
{
    struct ast_config *cfg;
    struct ast_flags config_flags = {0};
    int ret;
    void*  context;

    DEBUG("%s\n", "Loading zmq manager Config");
    cfg = ast_config_load(g_app.config_name, config_flags);
    if ((cfg == NULL) || (cfg == CONFIG_STATUS_FILEINVALID))
    {
        ast_log(LOG_WARNING, "Unable to load config for zmq manager: %s\n", g_app.config_name);
        return AST_MODULE_LOAD_FAILURE;
    }
    else if (cfg == CONFIG_STATUS_FILEUNCHANGED)
    {
        return AST_MODULE_LOAD_SUCCESS;
    }

    // cmd socket
    ret  = load_config_string(cfg, "global", "addr_cmd", &g_app.addr_cmd, "tcp://*:967");
    if(ret < 0)
    {
        DEBUG("%s\n", "Could not load connection_string");
        return AST_MODULE_LOAD_FAILURE;
    }
    DEBUG("cmd address. addr[%s]\n", ast_str_buffer(g_app.addr_cmd));

    // evt socket
    ret  = load_config_string(cfg, "global", "addr_evt", &g_app.addr_evt, "tcp://*:968");
    if(ret < 0)
    {
        DEBUG("%s\n", "Could not load connection_string");
        return AST_MODULE_LOAD_FAILURE;
    }
    DEBUG("evt address. addr[%s]\n", ast_str_buffer(g_app.addr_evt));

    ast_config_destroy(cfg);

    context = zmq_ctx_new();

    // Make cmd socket
    g_app.sock_cmd = zmq_socket(context, ZMQ_REP);
    if(g_app.sock_cmd == NULL)
    {
        ERROR("Couldn't created the new socket [%s]\n", strerror(errno));
        zmq_close (g_app.sock_cmd);
        zmq_term (context);
        return false;
    }

    ret = zmq_bind(g_app.sock_cmd, ast_str_buffer(g_app.addr_cmd));
    if(ret == -1)
    {
        ERROR("Couldn't bind [%s]\n", strerror(errno));
        zmq_close (g_app.sock_cmd);
        zmq_term (context);
        return false;
    }

    // Make evt socket
    g_app.sock_evt = zmq_socket(context, ZMQ_PUB);
    if(g_app.sock_evt == NULL)
    {
        ERROR("Couldn't created the evt socket [%s]\n", strerror(errno));
        zmq_close (g_app.sock_evt);
        zmq_term (context);
        return false;
    }

    ret = zmq_bind(g_app.sock_evt, ast_str_buffer(g_app.addr_evt));
    if(ret == -1)
    {
        ERROR("Couldn't bind [%s]\n", strerror(errno));
        zmq_close (g_app.sock_evt);
        zmq_term (context);
        return false;
    }

    DEBUG("%s\n", "About to call ast_zmq_start");
    ret = ast_zmq_start();

    return AST_MODULE_LOAD_SUCCESS;

}

static int load_module(void)
{
    int ret;

    ret = asprintf(&g_app.config_name, "zmq_manager.conf");

    ret = _load_module();
    if(ret != AST_MODULE_LOAD_SUCCESS)
    {
        ERROR("Could not load module! ret[%d]\n", ret);
        return AST_MODULE_LOAD_FAILURE;
    }

    DEBUG("%s\n", "Load correctly..");
    ret = ast_cli_register_multiple(cli_zmq_manager_evt, ARRAY_LEN(cli_zmq_manager_evt));

    return AST_MODULE_LOAD_SUCCESS;
//    return ret ? AST_MODULE_LOAD_DECLINE : AST_MODULE_LOAD_SUCCESS;
}

/**
 * zmq command msg handler
 * @param data
 */
static void zmq_cmd_handler(void *data)
{

//    zmq_data_t* zmq_data;
//    struct ast_json*     j_tmp;
//    char*       tmp;
//
//    zmq_data = (zmq_data_t*)data;
//
//    DEBUG("%s\n", "test start4.");
//
////    tmp = malloc(1000);
//
//    j_tmp = ast_json_deep_copy(zmq_data->j_recv);
//    tmp = ast_json_dump_string(j_tmp);
////    DEBUG("dumps[%s]\n", tmp);
////
//    free(tmp);
//
//    DEBUG("%s\n", "test end.");


    int ret;
    struct ast_json* j_tmp;
    zmq_data_t*     zmq_data;
    char*           tmp;
    struct manager_custom_hook* hook;
    const char *key;
    struct ast_json *value;
    char* str_resp;
    char str_cmd[10000];
    struct ast_json_iter* j_iter;

    DEBUG("zmq_cmd_handler!! data[%p]\n", data);

    zmq_data = (zmq_data_t*)data;

    // just for log
    j_tmp = ast_json_deep_copy(zmq_data->j_recv);
    tmp = ast_json_dump_string(j_tmp);
    if(tmp == NULL)
    {
        ERROR("%s\n", "Could not parsing.");
        return;
    }
    DEBUG("ast_start_worker. msg[%s]\n", tmp);
    ast_json_free(tmp);
    ast_json_unref(j_tmp);

    DEBUG("ast_start_worker. msg[%s]\n", "test2");


    memset(str_cmd, 0x00, sizeof(str_cmd));
    // Get action
    j_tmp = ast_json_object_get(zmq_data->j_recv, "action");
    if(j_tmp == NULL)
    {
        ERROR("%s\n", "Could not get the action.");
        return;
    }
    sprintf(str_cmd, "action:%s\n", ast_json_string_get(j_tmp));

    for(j_iter = ast_json_object_iter(zmq_data->j_recv);
            j_iter != NULL;
            j_iter = ast_json_object_iter_next(zmq_data->j_recv, j_iter))
    {
        tmp = ast_json_object_iter_key(j_iter);
        ret = strcmp(tmp, "action");
        if(ret == 0)
        {
            continue;
        }
        sprintf(str_cmd, "%s%s:%s\n", str_cmd, tmp, ast_json_string_get(ast_json_object_iter_value(j_iter)));
    }


//    {
//        ret = strcmp(key, "action");
//        if(ret == 0)
//        {
//            continue;
//        }
//        sprintf(str_cmd, "%s%s:%s\n", str_cmd, key, json_string_value(value));
//    }
    sprintf(str_cmd, "%s\n", str_cmd);

    DEBUG("action command. command[%s]\n", str_cmd);

    // Set hook
    hook = calloc(1, sizeof(struct manager_custom_hook));
//    hook->file = __FILE__;
    hook->file = NULL;
    hook->helper = &zmq_cmd_helper;

//    g_json_res = json_object();
    if(g_json_res_tmp != NULL)
    {
        ast_json_unref(g_json_res_tmp);
        g_json_res_tmp = NULL;
    }

    if(g_json_res != NULL)
    {
        ast_json_unref(g_json_res);
        g_json_res = NULL;
    }

    g_json_res = ast_json_array_create();
    ret = ast_hook_send_action(hook, str_cmd);
    if(ret != 0)
    {
        free(hook);
        return;
    }

    str_resp = ast_json_dump_string(g_json_res);
    ast_json_unref(g_json_res);
    if(str_resp == NULL)
    {
        return;
    }

    ret = zmq_send(zmq_data->zmq_sock, str_resp, strlen(str_resp), 0);
    if(ret == -1)
    {
        ERROR("Could not send message. err[%d:%s]\n", errno, strerror(errno));
    }
    DEBUG("set_hook_send_action. ret[%d], msg[%s]\n", ret, str_resp);

    free(hook);
    free(str_resp);
}

/**
 * Main thread starter.
 *
 * Starts the main thread.
 */
static int ast_zmq_start(void)
{
    int ret;

    // cmd sock
    DEBUG("%s\n", "start zmq cmd thread");
    ret = ast_pthread_create_background(&g_app.pth_cmd, NULL, (void*)&zmq_cmd_thread, NULL);
    if(ret > 0)
    {
        ERROR("Unable to launch thread for action cmd. err[%s]\n", strerror(errno));
        return false;
    }

//    while(1)
//    {
//        char* tmp = "{\"test\": \"333\"}";
//        char* tmp_out;
//
//        struct ast_json* j_out;
//        struct ast_json* j_tmp;
//        struct ast_json_error error;
//
//        j_out = ast_json_load_buf(tmp, strlen(tmp), &error);
//        j_tmp = ast_json_deep_copy(j_out);
//        tmp_out = ast_json_dump_string(j_tmp);
//
//        DEBUG("%s\n", tmp_out);
//        ast_json_free(tmp_out);
//
//        DEBUG("%s\n", "good test");
//
//
//        usleep(10000);
//    }

    // evt sock
    DEBUG("%s\n", "start zmq evt thread");
    struct manager_custom_hook* hook;
    hook = calloc(1, sizeof(struct manager_custom_hook));
    hook->file = __FILE__;
    hook->helper = &zmq_evt_helper;
    DEBUG("%s\n", "Before hook");
    ast_manager_register_hook(hook);
    DEBUG("%s\n", "After hook");

    return true;
}

static void trim(char * s)
{
    char * p = s;
    int l = strlen(p);

    while(isspace(p[l - 1])) p[--l] = 0;
    while(* p && isspace(* p)) ++p, --l;

    memmove(s, p, l + 1);
}


static int zmq_evt_helper(int category, const char *event, char *content)
{

    struct ast_json* j_out;
    struct ast_json* j_tmp;
    int i;
    int ret;
    int cnt;
    char* line;
    char* key;
    char* value;
    char** parse;
    char*  buf_send;

    DEBUG("zmq_evt_handler. category[%d], event[%s], content[%s]\n", category, event, content);

    parse = calloc(1024, sizeof(char*));

    line = strtok(content, "\n");
    parse[0] = strdup(line);

    cnt = 1;
    while(true)
    {
        line = strtok(NULL, "\n");
        if(line == NULL)
        {
            break;
        }
        ret = strlen(line);
        if(ret < 2)
        {
            break;
        }

        parse[cnt] = strdup(line);
        cnt++;
    }

    // parse
    DEBUG("check. cnt[%d]\n", cnt);
    j_out = ast_json_object_create();
    for(i = 0; i < cnt; i++)
    {
        key = strtok(parse[i], ":");
        value = strtok(NULL, ":");
        trim(key);
        trim(value);
        j_tmp = ast_json_string_create(value);
        ast_json_object_set(j_out, key, j_tmp);
        ast_json_unref(j_tmp);

        DEBUG("parse[%s], key[%s], value[%s]\n", parse[i], key, value);
    }

    buf_send = ast_json_dump_string(j_out);
    ret = zmq_send(g_app.sock_evt,  buf_send, strlen(buf_send), 0);
    DEBUG("send buf. ret[%d], buf[%s]\n", ret, buf_send);

    // free
    for(i = 0; i < 1024; i++)
    {
        if(parse[i] == NULL)
        {
            break;
        }
        free(parse[i]);
    }
    free(parse);
    ast_json_unref(j_out);
    free( buf_send);

    return 0;


//    key = strtok(content, ":");
//    value = strtok(NULL, "\r");
//
//    json_object_set(g_json_evt, key, json_string(value));
//
//    tmp = strtok(NULL, "\r");
//    if(tmp == value)
//    {
//        return;
//    }
//
//    // send to client
//    buf = json_dumps(g_json_evt, JSON_INDENT(1));
//    zmq_send(g_app.sock_evt, buf, strlen(buf), 0);
//    free(buf);
//    json_decref(g_json_evt);

    return true;
}


AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "ZMQ Manager Module");
