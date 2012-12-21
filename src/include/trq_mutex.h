/*
*         OpenPBS (Portable Batch System) v2.3 Software License
*
* Copyright (c) 1999-2010 Veridian Information Solutions, Inc.
* All rights reserved.
*
* ---------------------------------------------------------------------------
* For a license to use or redistribute the OpenPBS software under conditions
* other than those described below, or to purchase support for this software,
* please contact Veridian Systems, PBS Products Department ("Licensor") at:
*
*    www.OpenPBS.org  +1 650 967-4675                  sales@OpenPBS.org
*                        877 902-4PBS (US toll-free)
* ---------------------------------------------------------------------------
*
* This license covers use of the OpenPBS v2.3 software (the "Software") at
* your site or location, and, for certain users, redistribution of the
* Software to other sites and locations.  Use and redistribution of
* OpenPBS v2.3 in source and binary forms, with or without modification,
* are permitted provided that all of the following conditions are met.
* After December 31, 2001, only conditions 3-6 must be met:
*
* 1. Commercial and/or non-commercial use of the Software is permitted
*    provided a current software registration is on file at www.OpenPBS.org.
*    If use of this software contributes to a publication, product, or
*    service, proper attribution must be given; see www.OpenPBS.org/credit.html
*
* 2. Redistribution in any form is only permitted for non-commercial,
*    non-profit purposes.  There can be no charge for the Software or any
*    software incorporating the Software.  Further, there can be no
*    expectation of revenue generated as a consequence of redistributing
*    the Software.
*
* 3. Any Redistribution of source code must retain the above copyright notice
*    and the acknowledgment contained in paragraph 6, this list of conditions
*    and the disclaimer contained in paragraph 7.
*
* 4. Any Redistribution in binary form must reproduce the above copyright
*    notice and the acknowledgment contained in paragraph 6, this list of
*    conditions and the disclaimer contained in paragraph 7 in the
*    documentation and/or other materials provided with the distribution.
*
* 5. Redistributions in any form must be accompanied by information on how to
*    obtain complete source code for the OpenPBS software and any
*    modifications and/or additions to the OpenPBS software.  The source code
*    must either be included in the distribution or be available for no more
*    than the cost of distribution plus a nominal fee, and all modifications
*    and additions to the Software must be freely redistributable by any party
*    (including Licensor) without restriction.
*
* 6. All advertising materials mentioning features or use of the Software must
*    display the following acknowledgment:
*
*     "This product includes software developed by NASA Ames Research Center,
*     Lawrence Livermore National Laboratory, and Veridian Information
*     Solutions, Inc.
*     Visit www.OpenPBS.org for OpenPBS software support,
*     products, and information."
*
* 7. DISCLAIMER OF WARRANTY
*
* THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. ANY EXPRESS
* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
* ARE EXPRESSLY DISCLAIMED.
*
* IN NO EVENT SHALL VERIDIAN CORPORATION, ITS AFFILIATED COMPANIES, OR THE
* U.S. GOVERNMENT OR ANY OF ITS AGENCIES BE LIABLE FOR ANY DIRECT OR INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
* OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* This license will be governed by the laws of the Commonwealth of Virginia,
* without reference to its choice of law rules.
*/

/* Multiple inclusion prevention.  The new way: */
#pragma once
/* and the old way: */
#if defined(TRQ_MUTEX_WRAPPERS) && !defined(TRQ_MUTEX_H)
#  define TRQ_MUTEX_H

/* System headers */
#  include <pthread.h>
#  include <errno.h>
#  include <string.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <syslog.h>
#  include <unistd.h>
#  include <sys/syscall.h>
#  include <execinfo.h>

/* Turns on trace logging to syslog.  This will generate hundreds of
   thousands of messages very quickly.  If your syslogd is rate
   limited, you will miss most of them.  If it's not, the results are
   unspecified....  Use with extreme caution or not at all. */
#  ifndef TRQ_MUTEX_LOG_DEBUG
#    define TRQ_MUTEX_LOG_DEBUG 0
#  endif

/* Check for and trap/report on same-thread deadlocks. */
#  ifndef TRQ_MUTEX_DEADLOCK_CHECK
#    define TRQ_MUTEX_DEADLOCK_CHECK 1
#  endif

/* Make sure we own a mutex before unlocking it. */
#  ifndef TRQ_MUTEX_OWNER_CHECK
#    define TRQ_MUTEX_OWNER_CHECK 0
#  endif

/* Make sure we own a mutex before waiting on it. */
#  ifndef TRQ_MUTEX_WAIT_OWNER_CHECK
#    define TRQ_MUTEX_WAIT_OWNER_CHECK 1
#  endif

/* Maximum number of addresses we can store for stack trace.  Static for speed. */
#  define TRQ_MUTEX_STACKSIZE  32

/* Structure to hold source location information */
typedef struct trq_identity_t_struct {
    pid_t thread;                      /* Thread ID (i.e., PID) */
    char *func;                        /* Function name */
    char *file;                        /* File name */
    size_t line;                       /* Line number */
    void *stack[TRQ_MUTEX_STACKSIZE];  /* Stack addresses */
    int stacksize;                     /* Number of addresses */
} trq_identity_t;

/* Structure for wrapping mutexes */
typedef struct trq_mutex_t_struct {
    pthread_mutex_t pt_mutex;   /* The mutex itself */
    char *name;                 /* Variable name of the mutex */
    trq_identity_t locker;      /* Where mutex was last locked */
} trq_mutex_t;

/* How we get our local thread ID */
#  ifdef SYS_gettid
#    define trq_mutex_gettid() (syscall(SYS_gettid))
#  else
#    define trq_mutex_gettid() (-1)
#  endif

/* Not all OSs can safely printf() a NULL string. */
#  define SAFE_PRINTSTR(s)     ((s) ? (s) : ("(null)"))

/* Store stack trace address array into variables provided. */
#  define trq_mutex_getstack(stack, size) \
          do { (size) = backtrace((stack), (size)); } while (0)
/* Dump stack trace to syslog from variables provided with given level (l) and leader (s). */
#  define trq_mutex_showstack(id, stack, size, l, s)                    \
          do {                                                          \
              int i;                                                    \
              char **stack_strings;                                     \
                                                                        \
              stack_strings = backtrace_symbols((stack), (size));       \
              if (stack_strings) {                                      \
                  for (i = 0; i < (size); i++) {                        \
                      syslog((l), "%ld:  %s:  %2d:  %s\n",              \
                             (long) (id), (s), i, stack_strings[i]);    \
                  }                                                     \
                  free(stack_strings);                                  \
              } else {                                                  \
                  syslog((l), "%ld:  %s:  Stack trace unavailable:  %s\n", \
                         (long) (id), (s), strerror(errno));            \
              }                                                         \
          } while (0)
/* Dump current stack to syslog with given leader. */
#  define trq_mutex_stacktrace(id, l, s)                                \
          do {                                                          \
              void *stack[TRQ_MUTEX_STACKSIZE];                         \
              int stacksize = TRQ_MUTEX_STACKSIZE;                      \
                                                                        \
              trq_mutex_getstack(stack, stacksize);                     \
              trq_mutex_showstack((id), stack, stacksize, (l), (s));    \
          } while (0)

/* Initialize source location structure (trq_identity_t). */
#  define trq_mutex_identity_init(t)                                    \
          do {                                                          \
              (t).thread = 0;                                           \
              (t).func = NULL;                                          \
              (t).file = NULL;                                          \
              (t).line = 0;                                             \
              (t).stacksize = 0;                                        \
          } while (0)
#  define trq_mutex_identity_clear(t) trq_mutex_identity_init(t)
#  define trq_mutex_identity_set(t, i, fn, f, l)                        \
          do {                                                          \
              (t).thread = (i);                                         \
              (t).func = (char *) (fn);                                 \
              (t).file = (char *) (f);                                  \
              (t).line = (size_t) (l);                                  \
              trq_mutex_getstack((t).stack, (t).stacksize);             \
          } while (0)

static inline int
_trq_mutex_init(trq_mutex_t *trqm, const pthread_mutexattr_t *attr,
                const char *name, const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    if (!trqm) {
        return EINVAL;
    }
    thr_id = trq_mutex_gettid();
    trqm->name = (char *) name;
    trq_mutex_identity_init(trqm->locker);
    retval = pthread_mutex_init(&trqm->pt_mutex, attr);

    openlog(NULL, LOG_PID, LOG_DAEMON);
#if TRQ_MUTEX_LOG_DEBUG
    syslog(LOG_DEBUG, "%ld:  pthread_mutex_init(%s[%p], %ld) in %s() at %s:%ld returned %d (%s)",
           (long) thr_id, name, trqm, (long) attr, func, file, line, retval, strerror(retval));
#endif
    return retval;
    /* Simulate using the variables to avoid gcc warnings without changing resulting binary. */
    if (line) name = NULL; func = NULL; file = NULL;
}

static inline int
_trq_mutex_destroy(trq_mutex_t *trqm, const char *name, const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }
    retval = pthread_mutex_destroy(&trqm->pt_mutex);
    trqm->name = NULL;
    trq_mutex_identity_clear(trqm->locker);

#if TRQ_MUTEX_LOG_DEBUG
    syslog(LOG_DEBUG, "%ld:  pthread_mutex_destroy(%s[%p]) in %s() at %s:%ld returned %d (%s)",
           (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
#endif
    return retval;
    /* Simulate using the variables to avoid gcc warnings without changing resulting binary. */
    if (line) name = NULL; func = NULL; file = NULL;
}

static inline int
_trq_mutex_lock(trq_mutex_t *trqm, const char *name, const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }
#if TRQ_MUTEX_DEADLOCK_CHECK
    if (trqm->locker.thread == thr_id) {
        syslog(LOG_ERR, "%ld:  pthread_mutex_lock(%s[%p]) in %s() at %s:%ld almost deadlocked."
               "  Locked by %ld in %s() at %s:%ld",
               (long) thr_id, name, trqm, func, file, line, (long) trqm->locker.thread,
               SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file), trqm->locker.line);
        trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_ERR, "  Locker stack");
        trq_mutex_stacktrace(thr_id, LOG_ERR, "  Current stack");
        return 0;
    }
#endif

    retval = pthread_mutex_lock(&trqm->pt_mutex);
    if (!retval) {
        trq_mutex_identity_set(trqm->locker, thr_id, func, file, line);
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_mutex_lock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
#endif
    } else {
        syslog(LOG_WARNING, "%ld:  pthread_mutex_lock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
    }
    return retval;
}

static inline int
_trq_mutex_unlock(trq_mutex_t *trqm, const char *name, const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }
#if TRQ_MUTEX_OWNER_CHECK
    if (trqm->locker.thread != thr_id) {
        syslog(LOG_ERR, "%ld:  pthread_mutex_unlock(%s[%p]) in %s() at %s:%ld not owned by me."
               "  Locked by %ld in %s() at %s:%ld",
               (long) thr_id, name, trqm, func, file, line, (long) trqm->locker.thread,
               SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file), trqm->locker.line);
        trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_ERR, "  Locker stack");
        trq_mutex_stacktrace(thr_id, LOG_ERR, "  Current stack");
        return 0;
    }
#endif

    trq_mutex_identity_clear(trqm->locker);
    retval = pthread_mutex_unlock(&trqm->pt_mutex);
    if (retval) {
        syslog(LOG_WARNING, "%ld:  pthread_mutex_unlock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
    } else {
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_mutex_unlock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
#endif
    }
    return retval;
}

static inline int
_trq_mutex_trylock(trq_mutex_t *trqm, const char *name, const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }

    retval = pthread_mutex_trylock(&trqm->pt_mutex);
    if (!retval) {
        trq_mutex_identity_set(trqm->locker, thr_id, func, file, line);
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_mutex_trylock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
#endif
    } else if (retval == EBUSY) {
        if (trqm->locker.thread == thr_id) {
            syslog(LOG_WARNING, "%ld:  pthread_mutex_trylock(%s[%p]) in %s() at %s:%ld avoided deadlock."
                   "  Locked by %ld in %s() at %s:%ld",
                   (long) thr_id, name, trqm, func, file, line, (long) trqm->locker.thread,
                   SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file), trqm->locker.line);
            trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_WARNING, "  Locker stack");
            trq_mutex_stacktrace(thr_id, LOG_WARNING, "  Current stack");
        } else {
#if TRQ_MUTEX_LOG_DEBUG
            syslog(LOG_DEBUG, "%ld:  pthread_mutex_trylock(%s[%p]) in %s() at %s:%ld detected lock."
                   "  Locked by %ld in %s() at %s:%ld",
                   (long) thr_id, name, trqm, func, file, line, (long) trqm->locker.thread,
                   SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file), trqm->locker.line);
            trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_DEBUG, "  Locker stack");
            trq_mutex_stacktrace(thr_id, LOG_DEBUG, "  Current stack");
#endif
        }
    } else {
        syslog(LOG_WARNING, "%ld:  pthread_mutex_trylock(%s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, name, trqm, func, file, line, retval, strerror(retval));
    }
    return retval;
}

static inline int
_trq_cond_timedwait(pthread_cond_t *cond, const char *cond_name,
                    trq_mutex_t *trqm, const char *name,
                    const struct timespec *abstime, const char *abstime_name,
                    const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }
#if TRQ_MUTEX_WAIT_OWNER_CHECK
    if (trqm->locker.thread != thr_id) {
        syslog(LOG_ERR, "%ld:  pthread_cond_timedwait(%s[%p], %s[%p], %s[%p]) in %s() at %s:%ld caught unowned mutex."
               "  Locked by %ld in %s() at %s:%ld",
               (long) thr_id, cond_name, cond, name, trqm, abstime_name, abstime, func, file, line,
               (long) trqm->locker.thread, SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file),
               trqm->locker.line);
        trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_ERR, "  Locker stack");
        trq_mutex_stacktrace(thr_id, LOG_ERR, "  Current stack");
        return 0;
    }
#endif

    retval = pthread_cond_timedwait(cond, &trqm->pt_mutex, abstime);
    if (!retval) {
        trq_mutex_identity_set(trqm->locker, thr_id, func, file, line);
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_cond_timedwait(%s[%p], %s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, abstime_name, abstime, func, file, line, retval, strerror(retval));
#endif
    } else if (retval != ETIMEDOUT) {
        syslog(LOG_WARNING, "%ld:  pthread_cond_timedwait(%s[%p], %s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, abstime_name, abstime, func, file, line, retval, strerror(retval));
    } else {
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_cond_timedwait(%s[%p], %s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, abstime_name, abstime, func, file, line, retval, strerror(retval));
#endif
    }
    return retval;
}

static inline int
_trq_cond_wait(pthread_cond_t *cond, const char *cond_name,
               trq_mutex_t *trqm, const char *name,
               const char *func, const char *file, const size_t line)
{
    int retval;
    pid_t thr_id;

    thr_id = trq_mutex_gettid();
    if (!trqm) {
        return EINVAL;
    }
#if TRQ_MUTEX_WAIT_OWNER_CHECK
    if (trqm->locker.thread != thr_id) {
        syslog(LOG_ERR, "%ld:  pthread_cond_wait(%s[%p], %s[%p]) in %s() at %s:%ld caught unowned mutex."
               "  Locked by %ld in %s() at %s:%ld",
               (long) thr_id, cond_name, cond, name, trqm, func, file, line,
               (long) trqm->locker.thread, SAFE_PRINTSTR(trqm->locker.func), SAFE_PRINTSTR(trqm->locker.file),
               trqm->locker.line);
        trq_mutex_showstack(thr_id, trqm->locker.stack, trqm->locker.stacksize, LOG_ERR, "  Locker stack");
        trq_mutex_stacktrace(thr_id, LOG_ERR, "  Current stack");
        return 0;
    }
#endif

    retval = pthread_cond_wait(cond, &trqm->pt_mutex);
    if (!retval) {
        trq_mutex_identity_set(trqm->locker, thr_id, func, file, line);
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_cond_wait(%s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, func, file, line, retval, strerror(retval));
#endif
    } else if (retval != ETIMEDOUT) {
        syslog(LOG_WARNING, "%ld:  pthread_cond_wait(%s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, func, file, line, retval, strerror(retval));
    } else {
#if TRQ_MUTEX_LOG_DEBUG
        syslog(LOG_DEBUG, "%ld:  pthread_cond_wait(%s[%p], %s[%p]) in %s() at %s:%ld returned %d (%s)",
               (long) thr_id, cond_name, cond, name, trqm, func, file, line, retval, strerror(retval));
#endif
    }
    return retval;
}


#  define pthread_mutex_init(m, a)     (_trq_mutex_init((m), (a), (#m), __func__, __FILE__, __LINE__))
#  define pthread_mutex_destroy(m)     (_trq_mutex_destroy((m), (#m), __func__, __FILE__, __LINE__))
#  define pthread_mutex_lock(m)        (_trq_mutex_lock((m), (#m), __func__, __FILE__, __LINE__))
#  define pthread_mutex_unlock(m)      (_trq_mutex_unlock((m), (#m), __func__, __FILE__, __LINE__))
#  define pthread_mutex_trylock(m)     (_trq_mutex_trylock((m), (#m), __func__, __FILE__, __LINE__))
#  define pthread_mutex_t              trq_mutex_t

#  define pthread_cond_timedwait(c, m, a) (_trq_cond_timedwait((c), (#c), (m), (#m), (a), (#a), __func__, __FILE__, __LINE__))
#  define pthread_cond_wait(c, m)         (_trq_cond_wait((c), (#c), (m), (#m), __func__, __FILE__, __LINE__))
#endif /* defined(TRQ_MUTEX_WRAPPERS) && !defined(TRQ_MUTEX_H) */
