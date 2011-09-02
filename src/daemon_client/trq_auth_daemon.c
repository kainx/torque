#include "license_pbs.h" /* See here for the software license */
#include "trq_auth_daemon.h"

#include <stdlib.h> /* calloc, free */
#include <stdio.h> /* printf */
#include <string.h> /* strcat */
#include <pthread.h> /* threading functions */
#include "pbs_error.h" /* PBSE_NONE */
#include "pbs_constants.h" /* AUTH_IP */
#include "../lib/Libnet/lib_net.h" /* start_listener */
#include "../lib/Libifl/lib_ifl.h" /* process_svr_conn */

int load_config(
    char **ip,
    int *t_port,
    int *d_port)
  {
  int rc = PBSE_NONE;
  char *tmp_ip;
  /* Assume TORQUE_HOME = /var/spool/torque */
  /* /var/spool/torque/server_name */
  tmp_ip = (char *)calloc(1, 16);
  strcat(tmp_ip, "kahiko");
  *ip = tmp_ip;
  *t_port = 15001;
  *d_port = 15005;
  return rc;
  }

int load_ssh_key(
    char **ssh_key)
  {
  int rc = PBSE_NONE;
  return rc;
  }

int validate_server(
    char *t_server_ip,
    int t_server_port,
    char *ssh_key,
    char **sign_key)
  {
  int rc = PBSE_NONE;
  return rc;
  }

int trq_main(
    int argc,
    char **argv,
    char **envp)
  {
  int rc = PBSE_NONE;
  char *trq_server_ip = NULL, *the_key = NULL;
  int trq_server_port = 0, daemon_port = 0;
  void *(*process_method)(void *) = process_svr_conn;
  if ((rc = load_config(&trq_server_ip, &trq_server_port, &daemon_port)) != PBSE_NONE)
    {
    }
  else if ((rc = load_ssh_key(&the_key)) != PBSE_NONE)
    {
    }
  else if ((rc = start_listener(AUTH_IP, daemon_port, process_method)) != PBSE_NONE)
    {
    }
  else
    {
    printf("Daemon exit requested\n");
    }
  if (trq_server_ip != NULL)
    free(trq_server_ip);
  if (the_key != NULL)
    free(the_key);
  return rc;
  }