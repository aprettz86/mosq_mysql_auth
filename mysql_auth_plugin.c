/*
 * Copyright (c) 2013 Andrea Pretto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Version History
 * Current Version: 0.0.1
 *
 * 0.0.1:
 *  First implementation, main features are:
 *    - basic authentication mechanism is ON, the plugin
 *      expect sha256 hashed password.
 *    - database parameter and column names are all configurable
 *    - support reconfiguration and reconnectionon reloading
 *    - try to reconnect at each authentication request if the
 *      connection was lost
 *  TODO
 *    - implement ACL policy [?? maybe]
 *    - support more hashing policies
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <mysql.h>
#include <openssl/sha.h>
#include <syslog.h>

/*
 * gcc -I<path to mosquitto src>/lib/ -I<path to mosquitto src>/src/ \
 * -fPIC -shared mysql_auth_plugin.c -o mysql_auth_plugin.so `mysql_config --cflags --libs` -lcrypto
 *
 * [libssl and libmysql development packages are required]
 *
 * Configuration example to put in mosquitto conf file:
 *
 * auth_plugin /<path to mysql_auth_plugin.so>/mysql_auth_plugin.so
 * auth_opt_db_hostname localhost
 * auth_opt_db_port     0
 * auth_opt_db_username root
 * auth_opt_db_password mysqlroot
 * auth_opt_db_database testdb
 * auth_opt_db_table    testtable
 * auth_opt_db_username_column_name user
 * auth_opt_db_password_column_name password
 * auth_opt_db_disabled_column_name disabled
 * auth_opt_log_type all
 * [information, error, warning, notice, debug, none, all]
 */

//#define TAG "[mysql_auth_plugin] "

#define QUERY_STRING_MAX_SIZE  (2048)
#define DIGEST_LENGTH          (SHA256_DIGEST_LENGTH)
#define DIGEST_STRING_LENGTH   (DIGEST_LENGTH * 2 + 1)

#define SYSLOG_IDENTITY        "mosq_mysql_auth"

void build_digest_string(const char *passwd, char *digest_string) {
    unsigned char digest[DIGEST_LENGTH];
    SHA256((unsigned char*)passwd, strlen(passwd), (unsigned char*)digest);

    int i;
    for(i = 0; i < DIGEST_LENGTH; i++)
         sprintf(&digest_string[i * 2], "%02x", (unsigned int)digest[i]);

    digest_string[DIGEST_STRING_LENGTH - 1] = '\0';
}


const char *param_db_hostname = "db_hostname";
const char *param_db_port     = "db_port";
const char *param_db_username = "db_username";
const char *param_db_password = "db_password";
const char *param_db_database = "db_database";
const char *param_db_table    = "db_table";
const char *param_db_username_column_name = "db_username_column_name";
const char *param_db_password_column_name = "db_password_column_name";
const char *param_db_disabled_column_name = "db_disabled_column_name";
const char *param_log_type = "log_type";

struct mysql_auth_data {
    MYSQL *connection;

    const char *param_db_hostname;
    int param_db_port;
    const char *param_db_username;
    const char *param_db_password;
    const char *param_db_database;
    const char *param_db_table;
    const char *param_db_username_column_name;
    const char *param_db_password_column_name;
    const char *param_db_disabled_column_name;
    int log_mask;
};

int mysql_auth_data_init(struct mysql_auth_data *data,
    struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    memset((void*)data, 0, sizeof(*data));

    data->log_mask = (LOG_MASK(LOG_INFO) | LOG_MASK(LOG_ERR) |
                      LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_NOTICE));


    int i, logmask = 0;
    for(i = 0; i < auth_opt_count; i++) {
        const char *key = auth_opts[i].key;
        const char *value = auth_opts[i].value;

        if (strcmp(key, param_db_hostname) == 0) {
            data->param_db_hostname = strdup(value);
        } else if (strcmp(key, param_db_username) == 0) {
            data->param_db_username = strdup(value);
        } else if (strcmp(key, param_db_password) == 0) {
            data->param_db_password = strdup(value);
        } else if (strcmp(key, param_db_database) == 0) {
            data->param_db_database = strdup(value);
        } else if (strcmp(key, param_db_table) == 0) {
            data->param_db_table = strdup(value);
        } else if (strcmp(key, param_db_username_column_name) == 0) {
            data->param_db_username_column_name = strdup(value);
        } else if (strcmp(key, param_db_password_column_name) == 0) {
            data->param_db_password_column_name = strdup(value);
        } else if (strcmp(key, param_db_disabled_column_name) == 0) {
            data->param_db_disabled_column_name = strdup(value);
        } else if (strcmp(key, param_db_port) == 0) {
            data->param_db_port = atoi(value);
        } else if (strcmp(key, param_log_type) == 0) {
            if (logmask == 0) {
                data->log_mask = 0;
                logmask = 1;
            }
            if (strcmp(value, "debug") == 0) {
                data->log_mask |= LOG_MASK(LOG_DEBUG);
            } else if (strcmp(value, "information") == 0) {
                data->log_mask |= LOG_MASK(LOG_INFO);
            } else if (strcmp(value, "error") == 0) {
                data->log_mask |= LOG_MASK(LOG_ERR);
            } else if (strcmp(value, "warning") == 0) {
                data->log_mask |= LOG_MASK(LOG_WARNING);
            } else if (strcmp(value, "notice") == 0) {
                data->log_mask |= LOG_MASK(LOG_NOTICE);
            } else if (strcmp(value, "none") == 0) {
                data->log_mask = LOG_UPTO(LOG_ALERT);
            } else if (strcmp(value, "all") == 0) {
                data->log_mask |= (LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG) |
                                   LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING) |
                                   LOG_MASK(LOG_NOTICE));
            }
        }
    }

    // check data
    return 0;
}

void mysql_auth_data_print(const struct mysql_auth_data *data) {
#define _PH(F) syslog(LOG_DEBUG, "%s: %s\n", #F, data->F)

    _PH(param_db_hostname);
    syslog(LOG_DEBUG, "param_db_port: %d\n", data->param_db_port);
    _PH(param_db_username);
    _PH(param_db_password);
    _PH(param_db_hostname);
    _PH(param_db_database);
    _PH(param_db_table);
    _PH(param_db_username_column_name);
    _PH(param_db_password_column_name);
    _PH(param_db_disabled_column_name);
    syslog(LOG_DEBUG, "param_log_type: %d\n", data->log_mask);
}

void mysql_auth_data_free(struct mysql_auth_data *data) {
#define _FH(F) free((void*)data->F)

    _FH(param_db_hostname);
    _FH(param_db_username);
    _FH(param_db_password);
    _FH(param_db_hostname);
    _FH(param_db_database);
    _FH(param_db_table);
    _FH(param_db_username_column_name);
    _FH(param_db_password_column_name);
    _FH(param_db_disabled_column_name);

    memset((void*)data, 0, sizeof(*data));
}

int mysql_mosq_connect(struct mysql_auth_data *data) {
    if (mysql_real_connect(data->connection,
                           data->param_db_hostname,
                           data->param_db_username,
                           data->param_db_password,
                           data->param_db_database,
                           data->param_db_port, NULL, 0) == NULL)
    {
        syslog(LOG_ERR, "mysql_real_connect: \"%s\"\n", mysql_error(data->connection));
        return 1;
    }
    return 0;
}

//
// checkPwd return 0 if the user is AUTHORIZED.
// checkPwd return > 0 if the user is NOT AUTHORIZED.
//
int mysql_check_pwd(struct mysql_auth_data *data, const char *mqtt_username, const char *mqtt_password) {
    int authorized = 1, mysql_err;
    int numFields, numRows;
    char queryString[QUERY_STRING_MAX_SIZE];
    char pwdHash[DIGEST_STRING_LENGTH];
    MYSQL *con = data->connection;

    syslog(LOG_DEBUG, "%s: username <%s>, password <%s>\n",
                       __PRETTY_FUNCTION__, mqtt_username, mqtt_password);

    if (mqtt_username == NULL || mqtt_password == NULL)
        return 1;

    snprintf(queryString, QUERY_STRING_MAX_SIZE,
        "SELECT %s FROM %s WHERE %s IS FALSE AND %s = \"%s\"",
        data->param_db_password_column_name,
        data->param_db_table,
        data->param_db_disabled_column_name,
        data->param_db_username_column_name, mqtt_username);

    syslog(LOG_DEBUG, "Query: \"%s\"\n", queryString);


    if (mysql_query(con, queryString)) {
        syslog(LOG_ERR, "mysql_query: \"%s\"\n", mysql_error(con));
        if (mysql_mosq_connect(data))
            return 1;
        else if (mysql_query(con, queryString)) {
            syslog(LOG_ERR, "mysql_query [retry]: \"%s\"\n", mysql_error(con));
            return 1;
        }
    }

    MYSQL_RES *result = mysql_store_result(con);

    if (result == NULL) {
        syslog(LOG_ERR, "mysql_store_result: \"%s\"\n", mysql_error(con));
        return authorized;
    }

    numRows = mysql_num_rows(result);
    numFields = mysql_num_fields(result);

    build_digest_string(mqtt_password, pwdHash);

    if (numRows < 1) {
        syslog(LOG_INFO, "User \"%s\" not found or not enabled\n", mqtt_username);
        authorized = 2;
        //mysql_free_result(result);
    } else if (numRows > 1) {
        syslog(LOG_ERR,
            "User \"%s\" has more than one row associated [WTF ??]\n", mqtt_username);
        authorized = 3;
        //mysql_free_result(result);
    } else if (numFields != 1) {
        syslog(LOG_ERR, "Wrong query: no culumn named \"%s\"\n",
            data->param_db_password_column_name);
        authorized = 4;
    } else {
        MYSQL_ROW row;

        row = mysql_fetch_row(result);
        if (strcmp(row[0], pwdHash) == 0) {
            syslog(LOG_INFO, "Password for \"%s\" is CORRECT\n", mqtt_username);
            authorized = 0;
        } else {
            syslog(LOG_INFO, "Password for \"%s\" is NOT CORRECT\n", mqtt_username);
            authorized = 5;
        }
    }
    mysql_free_result(result);
    return authorized;
}

int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    struct mysql_auth_data *data = malloc(sizeof(struct mysql_auth_data));

    *user_data = (void*)data;
    mysql_auth_data_init(data, auth_opts, auth_opt_count);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    struct mysql_auth_data* auth_data = (struct mysql_auth_data*)user_data;

    mysql_auth_data_free(auth_data);
    free(user_data);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    struct mysql_auth_data* auth_data = (struct mysql_auth_data*)user_data;

    mysql_auth_data_init(auth_data, auth_opts, auth_opt_count);

    openlog (SYSLOG_IDENTITY, LOG_CONS | LOG_PID | LOG_NDELAY, 0);

    setlogmask(auth_data->log_mask);
    syslog(LOG_DEBUG, __PRETTY_FUNCTION__);

    mysql_auth_data_print(auth_data);

    // open DB connection
    auth_data->connection = mysql_init(NULL);

    if (mysql_mosq_connect(auth_data))
        return MOSQ_ERR_AUTH;

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    struct mysql_auth_data* auth_data = (struct mysql_auth_data*)user_data;

    syslog(LOG_DEBUG, __PRETTY_FUNCTION__);
    closelog();

    mysql_close(auth_data->connection);
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
    syslog(LOG_DEBUG, "%s [This function does nothing]", __PRETTY_FUNCTION__ );

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
    struct mysql_auth_data* auth_data = (struct mysql_auth_data*)user_data;

    syslog(LOG_DEBUG, __PRETTY_FUNCTION__);

    if (mysql_check_pwd(auth_data, username, password))
        return MOSQ_ERR_AUTH;

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
    syslog(LOG_DEBUG, "%s [This function does nothing]", __PRETTY_FUNCTION__ );

    return MOSQ_ERR_AUTH;
}


