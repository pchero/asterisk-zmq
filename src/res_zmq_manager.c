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

#include "res_zmq_manager.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 338557 $")

//static struct app_ g_app;
struct app_* g_app = NULL;

static struct ast_json*  g_json_res = NULL;  //!< action cmd response(array)

static void zmq_cmd_thread(void);
static void trim(char * s);
static int zmq_cmd_handler(zmq_data_t* data);
static int ast_zmq_start(void);
static char* handle_cli_zmq_manager_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static int zmq_evt_helper(int category, const char *event, char *content);
static int zmq_cmd_helper(int category, const char *event, char *content);
static int line_parse(char* line);


static struct ast_cli_entry cli_zmq_manager_evt[] = {
    AST_CLI_DEFINE(handle_cli_zmq_manager_status, "Shows useful status about zmq manager"),
};

//static ast_mutex_t workers_mutex;
static AST_LIST_HEAD_STATIC(unload_strings, unload_string);


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
    int   ret;
    int   i, j;
    char* key;
    char* value;
    char  tmp[1024];
    char* dump;
    struct ast_json*    j_tmp;

    ast_log(LOG_NOTICE, "AMI Event: category[%d], event[%s], content[%s]\n", category, event, content);
    ret = strlen(content);
    if(ret < 3)
    {
        return 1;
    }

    i = 0;
    j = 0;
    memset(tmp, 0x00, sizeof(tmp));
    j_tmp = ast_json_object_create();
    for(i = 0; i < strlen(content); i++)
    {
        if(content[i] == '\r')
        {
            if(content[i + 1] == '\n')
            {
                ret = strlen(tmp);
                if(ret == 0)
                {
                    break;
                }

                value = strdup(tmp);
                dump = value;
                key = strsep(&value, ":");
                if(key == NULL)
                {
                    free(dump);
                    continue;
                }

                trim(key);
                trim(value);
                ast_json_object_set(j_tmp, key, ast_json_string_create(value));

                free(dump);
                memset(tmp, 0x00, sizeof(tmp));
                j = 0;
                i++;


                continue;
            }
        }
        tmp[j] = content[i];
        j++;
    }

    dump = ast_json_dump_string(j_tmp);
    DEBUG("Parsing dump. dump[%s]\n", dump);
    ast_json_free(dump);

    ret = ast_json_array_append(g_json_res, ast_json_deep_copy(j_tmp));
    ast_json_unref(j_tmp);
    j_tmp = NULL;
    if(ret == -1)
    {
        ERROR("Could not append json. ret[%d]\n", ret);
        return 0;
    }
    return 1;
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
static int load_config_string(
        struct ast_config *cfg,
        const char *category,
        const char *variable,
        struct ast_str **field,
        const char *def
        )
{
    struct unload_string *us;
    const char *tmp;

    if (!(us = ast_calloc(1, sizeof(*us))))
    {
        return -1;
    }

    if (!(*field = ast_str_create(16)))
    {
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
        DEBUG("Could not convert json. msg[%s], err[%d,%s]\n", msg, error.line, error.text);
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
    char* tmp;

    while(1)
    {
        opt_size = sizeof(opt);
        ret = zmq_getsockopt(g_app->sock_cmd, ZMQ_EVENTS, &opt, &opt_size);
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
        DEBUG("Recv thread. ret[%d], opt[%ld], sock[%p], buffer[%p]\n", ret, opt, g_app->sock_cmd, buffer);

        memset(buffer, 0x00, sizeof(buffer));
        size = zmq_recv(g_app->sock_cmd, buffer, MAX_RCV_BUF_LEN - 1, 0);
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
        DEBUG("Recv cmd. size[%d]\n", size);

        buffer[size] = '\0';
        DEBUG("Recv cmd. msg[%s]\n", buffer);

        zmq_data = calloc(1, sizeof(zmq_data_t));
        zmq_data->zmq_sock = g_app->sock_cmd;

        zmq_data->j_recv = recv_parse(buffer);
        if(zmq_data->j_recv == NULL)
        {
            ERROR("Could not parse msg. msg[%s]\n", buffer);
            zmq_send(zmq_data->zmq_sock, "[{\"Response\":\"Error\"},{\"Message\":\"PeInternal error.\"}]",
                    strlen("[{\"Response\":\"Error\"},{\"Message\":\"PeInternal error.\"}]"), 0);
            free(zmq_data);
            continue;
        }

        if(g_json_res != NULL)
        {
            ast_json_unref(g_json_res);
            g_json_res = NULL;
        }

        ret = zmq_cmd_handler(zmq_data);
        if(ret != 1)
        {
            zmq_send(zmq_data->zmq_sock, "[{\"Response\":\"Error\"},{\"Message\":\"PeInternal error.\"}]",
                    strlen("[{\"Response\":\"Error\"},{\"Message\":\"PeInternal error.\"}]"), 0);

            ast_json_unref(zmq_data->j_recv);
            free(zmq_data);
            continue;
        }

        tmp = ast_json_dump_string(g_json_res);
        DEBUG("Check dump. buf[%s]\n", tmp);
        ast_json_unref(g_json_res);
        g_json_res = NULL;
        if(tmp == NULL)
        {
            zmq_send(zmq_data->zmq_sock, "[{\"Error\":\"Response\"},{\"Message\":\"Internal error.\"}]]",
                    strlen("[{\"Error\":\"Response\"},{\"Message\":\"Internal error.\"}]]"), 0);

            ast_json_unref(zmq_data->j_recv);
            free(zmq_data);
            continue;
        }

        ret = zmq_send(zmq_data->zmq_sock, tmp, strlen(tmp), 0);
        if(ret == -1)
        {
            ERROR("Could not send message. err[%d:%s]\n", errno, strerror(errno));
        }
        DEBUG("set_hook_send_action. ret[%d], msg[%s]\n", ret, tmp);

        ast_json_free(tmp);
        ast_json_unref(zmq_data->j_recv);
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

    ast_cli(a->fd, "[cmd address: %s]\n", ast_str_buffer(g_app->addr_cmd));
    ast_cli(a->fd, "[evt address: %s]\n", ast_str_buffer(g_app->addr_evt));

    return CLI_SUCCESS;
}

/**
 * unload module
 * @return
 */
static int _unload_module(void)
{
    pthread_cancel(g_app->pth_cmd);
    pthread_kill(g_app->pth_cmd, SIGTERM);
    pthread_join(g_app->pth_cmd, NULL);

    zmq_close(g_app->sock_cmd);
    zmq_close(g_app->sock_evt);
    zmq_term(g_app->zmq_ctx);

    free(g_app->config_name);
    free(g_app->addr_evt);
    free(g_app->addr_cmd);

    ast_manager_unregister_hook(g_app->evt_hook);

    free(g_app);
    return 1;
}

static int unload_module(void)
{
    int ret;
    ast_log(LOG_NOTICE, "Unload res_zmq_module.\n");

    _unload_module();

    ast_manager_unregister_hook(&test_hook);

    ret = ast_cli_unregister_multiple(cli_zmq_manager_evt, ARRAY_LEN(cli_zmq_manager_evt));
    ast_log(LOG_DEBUG, "unregister finished. ret[%d]\n", ret);

    return AST_FORCE_SOFT;
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

    g_app = calloc(1, sizeof(struct app_));

    DEBUG("%s\n", "Loading zmq manager Config");
    ret = asprintf(&g_app->config_name, "zmq_manager.conf");
    cfg = ast_config_load(g_app->config_name, config_flags);
    if ((cfg == NULL) || (cfg == CONFIG_STATUS_FILEINVALID))
    {
        ast_log(LOG_WARNING, "Unable to load config for zmq manager: %s\n", g_app->config_name);
        return AST_MODULE_LOAD_FAILURE;
    }
    else if (cfg == CONFIG_STATUS_FILEUNCHANGED)
    {
        return AST_MODULE_LOAD_SUCCESS;
    }

    // cmd socket
    ret  = load_config_string(cfg, "global", "addr_cmd", &g_app->addr_cmd, "tcp://*:967");
    if(ret < 0)
    {
        DEBUG("%s\n", "Could not load connection_string");
        return AST_MODULE_LOAD_FAILURE;
    }
    DEBUG("cmd address. addr[%s]\n", ast_str_buffer(g_app->addr_cmd));

    // evt socket
    ret  = load_config_string(cfg, "global", "addr_evt", &g_app->addr_evt, "tcp://*:968");
    if(ret < 0)
    {
        DEBUG("%s\n", "Could not load connection_string");
        return AST_MODULE_LOAD_FAILURE;
    }
    DEBUG("evt address. addr[%s]\n", ast_str_buffer(g_app->addr_evt));

    ast_config_destroy(cfg);

    g_app->zmq_ctx = zmq_ctx_new();

    // Make cmd socket
    g_app->sock_cmd = zmq_socket(g_app->zmq_ctx, ZMQ_REP);
    if(g_app->sock_cmd == NULL)
    {
        ERROR("Couldn't created the new socket [%s]\n", strerror(errno));
        zmq_close (g_app->sock_cmd);
        zmq_term (g_app->zmq_ctx);
        return false;
    }

    ret = zmq_bind(g_app->sock_cmd, ast_str_buffer(g_app->addr_cmd));
    if(ret == -1)
    {
        ERROR("Couldn't bind [%s]\n", strerror(errno));
        zmq_close (g_app->sock_cmd);
        zmq_term (g_app->zmq_ctx);
        return false;
    }

    // Make evt socket
    g_app->sock_evt = zmq_socket(g_app->zmq_ctx, ZMQ_PUB);
    if(g_app->sock_evt == NULL)
    {
        ERROR("Couldn't created the evt socket [%s]\n", strerror(errno));
        zmq_close (g_app->sock_evt);
        zmq_term (g_app->zmq_ctx);
        return false;
    }

    ret = zmq_bind(g_app->sock_evt, ast_str_buffer(g_app->addr_evt));
    if(ret == -1)
    {
        ERROR("Couldn't bind [%s]\n", strerror(errno));
        zmq_close (g_app->sock_evt);
        zmq_term (g_app->zmq_ctx);
        return false;
    }

    DEBUG("%s\n", "About to call ast_zmq_start");
    ret = ast_zmq_start();

    return AST_MODULE_LOAD_SUCCESS;

}

/**
 * @brief Load module
 * @return
 */
static int load_module(void)
{
    int ret;

    ret = _load_module();
    if(ret != AST_MODULE_LOAD_SUCCESS)
    {
        ERROR("Could not load module! ret[%d]\n", ret);
        return AST_MODULE_LOAD_FAILURE;
    }

    DEBUG("%s\n", "Load correctly.");
    ret = ast_cli_register_multiple(cli_zmq_manager_evt, ARRAY_LEN(cli_zmq_manager_evt));

    return AST_MODULE_LOAD_SUCCESS;
}

/**
 * zmq command msg handler
 * @param data
 */
static int zmq_cmd_handler(zmq_data_t* zmq_data)
{

    int ret;
    struct ast_json* j_tmp;
    const char*     tmp_const;
    struct manager_custom_hook* hook;
    char* tmp;
    char str_cmd[10000];
    struct ast_json_iter* j_iter;

    DEBUG("zmq_cmd_handler!! data[%p]\n", zmq_data);

    // just for log
    j_tmp = ast_json_deep_copy(zmq_data->j_recv);
    tmp = ast_json_dump_string(j_tmp);
    if(tmp == NULL)
    {
        ERROR("%s\n", "Could not parsing.");
        return 0;
    }
    DEBUG("ast_start_worker. msg[%s]\n", tmp);
    ast_json_free(tmp);
    ast_json_unref(j_tmp);

    // Get action
    j_tmp = ast_json_object_get(zmq_data->j_recv, "Action");
    if(j_tmp == NULL)
    {
        ERROR("%s\n", "Could not get the action.");
        return 0;
    }

    memset(str_cmd, 0x00, sizeof(str_cmd));
    sprintf(str_cmd, "Action: %s\n", ast_json_string_get(j_tmp));
    ast_json_unref(j_tmp);

    for(j_iter = ast_json_object_iter(zmq_data->j_recv);
            j_iter != NULL;
            j_iter = ast_json_object_iter_next(zmq_data->j_recv, j_iter))
    {
        tmp_const = ast_json_object_iter_key(j_iter);
        ret = strcmp(tmp_const, "Action");
        if(ret == 0)
        {
            continue;
        }
        j_tmp = ast_json_object_iter_value(j_iter);
        sprintf(str_cmd, "%s%s: %s\n", str_cmd, tmp_const, ast_json_string_get(j_tmp));
        ast_json_unref(j_tmp);
    }

    DEBUG("action command. command[%s]\n", str_cmd);

    // Set hook
    hook = calloc(1, sizeof(struct manager_custom_hook));
    hook->file      = NULL;
    hook->helper    = &zmq_cmd_helper;

    g_json_res = ast_json_array_create();
    ret = ast_hook_send_action(hook, str_cmd);
    if(ret != 0)
    {
        ERROR("Could not hook. ret[%d], err[%d:%s]\n", ret, errno, strerror(errno));
        free(hook);
        return 0;
    }

    free(hook);
    return 1;
}

/**
 * Main thread starter.
 *
 * Starts the main thread.
 */
static int ast_zmq_start(void)
{
    int ret;
    struct manager_custom_hook* hook;

    // cmd sock
    ret = ast_pthread_create_background(&g_app->pth_cmd, NULL, (void*)&zmq_cmd_thread, NULL);
    if(ret > 0)
    {
        ERROR("Unable to launch thread for action cmd. err[%s]\n", strerror(errno));
        return false;
    }
    ast_log(LOG_NOTICE, "Start zmq_cmd thread.\n");

    // evt sock
    hook = calloc(1, sizeof(struct manager_custom_hook));
    hook->file = __FILE__;
    hook->helper = &zmq_evt_helper;
    ast_manager_register_hook(hook);
    g_app->evt_hook = hook;
    ast_log(LOG_NOTICE, "Start zmq_evt hook.\n");

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
    int j;
    int ret;
    char*   key;
    char*   value;
    char*   buf_send;
    char    tmp_line[4096];
    char*   tmp;
    char*   tmp_org;

    DEBUG("zmq_evt_handler. category[%d], event[%s], content[%s]\n", category, event, content);
    i = j = 0;
    memset(tmp_line, 0x00, sizeof(tmp_line));

    j_out = ast_json_object_create();
    for(i = 0; i < strlen(content); i++)
    {
        if((content[i] == '\r') && (content[i + 1] == '\n'))
        {
            ret = strlen(tmp_line);
            if(ret == 0)
            {
                break;
            }

            DEBUG("Check value. tmp_line[%s]\n", tmp_line);
            tmp = strdup(tmp_line);
            tmp_org = tmp;

            key = strsep(&tmp, ":");
            value = strsep(&tmp, ":");

            trim(key);
            trim(value);
            j_tmp = ast_json_string_create(value);
            ret = ast_json_object_set(j_out, key, j_tmp);

            free(tmp_org);
            memset(tmp_line, 0x00, sizeof(tmp_line));

            j = 0;
            i++;
            continue;
        }
        tmp_line[j] = content[i];
        j++;
    }

    buf_send = ast_json_dump_string(j_out);
    ret = zmq_send(g_app->sock_evt,  buf_send, strlen(buf_send), 0);
    DEBUG("Send event. ret[%d], buf[%s]\n", ret, buf_send);

    ast_json_free(buf_send);
    ast_json_unref(j_out);

    return 0;
}


AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "ZMQ Manager Module");
