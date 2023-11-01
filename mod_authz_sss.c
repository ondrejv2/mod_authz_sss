/*
 * Copyright 2022--2024 Ondrej Valousek
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"        /* for ap_hook_(check_user_id | auth_checker)*/
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authz_sss_module;

/* A handle for retrieving the requested file's group from mod_authnz_owner */
APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));

/* SSSD stuff - shamelessly copied from mod_identity_lookup */
#include <dbus/dbus.h>
#define DBUS_SSSD_PATH "/org/freedesktop/sssd/infopipe"
#define DBUS_SSSD_PATH_USERS "/org/freedesktop/sssd/infopipe/Users"
#define DBUS_SSSD_IFACE "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_IFACE_USERS "org.freedesktop.sssd.infopipe.Users"
#define DBUS_SSSD_GET_USER_GROUPS_METHOD "GetUserGroups"
#define DBUS_SSSD_GET_USER_ATTR_METHOD "GetUserAttr"
#define DBUS_SSSD_DEST "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_TIMEOUT 5000


static DBusMessage * lookup_identity_dbus_message(request_rec * r, DBusConnection * connection, DBusError * error, int timeout, const char * method, apr_hash_t * hash) {
        DBusMessage * message = dbus_message_new_method_call(DBUS_SSSD_DEST,
                DBUS_SSSD_PATH,
                DBUS_SSSD_IFACE,
                method);
        if (! message) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Error allocating dbus message");
                return NULL;
        }
        dbus_message_set_auto_start(message, TRUE);
                        
        char * user = r->user;
        int nargs = 0;
        const char ** args = NULL;
        if (hash && (nargs = apr_hash_count(hash))) {
                apr_hash_index_t * hi = apr_hash_first(r->pool, hash);
                args = apr_pcalloc(r->pool, nargs * sizeof(char *));
                for (int i = 0; hi; hi = apr_hash_next(hi), i++) {
                        const void * ptr; 
                        apr_hash_this(hi, &ptr, NULL, NULL);
                        args[i] = ptr;
                }       
        }               
        if (args) {
                dbus_message_append_args(message,
                        DBUS_TYPE_STRING, &user,
                        DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &args, nargs,
                        DBUS_TYPE_INVALID);
        } else {        
                dbus_message_append_args(message,
                        DBUS_TYPE_STRING, &user,
                        DBUS_TYPE_INVALID);
        }                       
        DBusMessage * reply = dbus_connection_send_with_reply_and_block(connection,
                message, timeout, error);
        dbus_message_unref(message);
        int is_error = 0;
        int reply_type = DBUS_MESSAGE_TYPE_ERROR;
        if (dbus_error_is_set(error)) {
                is_error = 1;
        } else {
                reply_type = dbus_message_get_type(reply);
                if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
                        is_error = 1;
                } else if (reply_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
                        is_error = 1;
                }
        }
        if (is_error) {
                char * args_string = "";
                if (args) {
                        int total_args_length = 0;
                        int i;
                        for (i = 0; i < nargs; i++) {
                                total_args_length += strlen(args[i]) + 2;
                        }
                        args_string = apr_palloc(r->pool, total_args_length + 1);
                        char * p = args_string;
                        for (i = 0; i < nargs; i++) {
                                strcpy(p, ", ");
                                strcpy(p + 2, args[i]);
                                p += strlen(args[i]) + 2;
                        }
                        args_string[total_args_length] = '\0';
                }
                if (dbus_error_is_set(error)) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Error dbus calling %s(%s%s): %s: %s", method, user, args_string, error->name, error->message);
                } else if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Error %s dbus calling %s(%s%s)", dbus_message_get_error_name(reply), method, user, args_string);
                } else {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "Error unexpected reply type %d dbus calling %s(%s%s)", reply_type, method, user, args_string);
                }
                if (reply) {
                        dbus_message_unref(reply);
                }
                return NULL;
        }
        return reply;
}
                                                                    
/* Check if the named user is in the given list of groups.  The list of
 * groups is a string with groups separated by white space.  Group ids
 * can either be unix group names or non-posix groups.  There must
 * be a unix login corresponding to the named user.
 */

static int check_sss_group(request_rec *r, const char *grouplist)
{
        DBusError error;
        dbus_error_init(&error);
        DBusConnection * connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
        DBusMessage * reply;
        int num;
        char ** ptr;

        if (! connection) {
              ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Error connecting to system dbus: %s", error.message);
              return 0;
        }
        dbus_connection_set_exit_on_disconnect(connection, FALSE);
        reply = lookup_identity_dbus_message(r, connection, &error, DBUS_SSSD_TIMEOUT, DBUS_SSSD_GET_USER_GROUPS_METHOD, NULL);
        if (reply && dbus_message_get_args(reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &ptr, &num, DBUS_TYPE_INVALID)) {
             for (int i = 0; i < num; i++) {
                    const char *grouplist_work = grouplist;

                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                                  "dbus call %s returned group %s", DBUS_SSSD_GET_USER_GROUPS_METHOD, ptr[i]);
                    /* Loop through list of groups passed in and see if any match */
                           while (*grouplist_work != '\0') {
                        char *w = ap_getword_conf(r->pool, &grouplist_work);
                        /* shall we use strcasecmp instead? SSSD always return lower case */
                        if (!strcmp(w, ptr[i]))
                        {
                            dbus_free_string_array(ptr);
                            dbus_message_unref(reply);
                            dbus_connection_unref(connection);
                            dbus_error_free(&error);
                            return 1;
                        }
                    }
             }
             dbus_free_string_array(ptr);
        }
        if (reply) {
             dbus_message_unref(reply);
        }
        dbus_connection_unref(connection);
        dbus_error_free(&error);
        return 0;
}

static authz_status group_check_authorization(request_rec *r,
        const char *require_args, const void *parsed_require_args)
{
    /* If no authenticated user, pass */
    if ( !r->user ) return AUTHZ_DENIED_NO_USER;

    if (check_sss_group(r,require_args))
        return AUTHZ_GRANTED;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "Authorization of user %s to access %s failed. "
        "User not in Required unix groups (%s).",
        r->user, r->uri, require_args);

    return AUTHZ_DENIED;
}

static const authz_provider authz_sss_provider =
{
    &group_check_authorization,
    NULL,
};

static void authz_sss_register_hooks(apr_pool_t *p)
{
    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "sss-group",
            AUTHZ_PROVIDER_VERSION,
            &authz_sss_provider, AP_AUTH_INTERNAL_PER_CONF);
}
    
module AP_MODULE_DECLARE_DATA authz_sss_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                                  /* create per-dir config */
    NULL,                                  /* merge per-dir config */
    NULL,                                  /* create per-server config */
    NULL,                                  /* merge per-server config */
    NULL,                                   /* command apr_table_t */
    authz_sss_register_hooks              /* register hooks */
};
