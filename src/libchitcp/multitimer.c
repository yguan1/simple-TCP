/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"

/* worker args used specifically for passing mt */
typedef struct timer_worker_args
{
    multi_timer_t *mt;
} timer_worker_args_t;

/*
 * thread_timers - where the multitimer thread lives in
 *
 * args: when creating thread, pass mt in it
 * 
 * Returns: none
 */
void *thread_timers(void *args)
{

    timer_worker_args_t *wa = (timer_worker_args_t*)args;
    multi_timer_t *mt = wa->mt;
    free(wa);

    pthread_mutex_lock(&mt->lock);
    /* the thread will not terminate until it is freed */
    /* it will be force-cancelled (pthread_cancel) when it is freed */
    while (!mt->termed)
    {
        /* block until there are active timers
         * (signal will be sent here by the function that adds the timer) */
        while (mt->active_timers == NULL)
        {
            pthread_cond_wait(&mt->cv_list_update, &mt->lock);
        }

        /* timing the first timer (with the earliest expire time) */
        while (mt->active_timers != NULL)
        {
            /* Note here active_timers also means the 1st timer in the list */
            single_timer_t *curr_timer = mt->active_timers;

            int ret; /* return value of cond wait */

            ret = pthread_cond_timedwait(&mt->cv_list_update, &mt->lock,
                                         &curr_timer->expire_time);

            /* If the wait ends with a timeout */
            if (ret == ETIMEDOUT)
            {
                mt_callback_func tmp_func = curr_timer->callback;
                void *tmp_args = curr_timer->callback_args;
                curr_timer->num_timeouts++;
                mt_cancel_timer(mt, curr_timer->id);
                tmp_func(mt, curr_timer, tmp_args);
            }

            /* If the wait ends with a cancel */

            /* Here the list should have already been updated by the function
             * that cancelled the timer, so if there are still active timers,
             * it will proceed with the next; if not, it will break and enter
             * the 1st small while loop. Hence, no need to do anything here */
        }
    }

    /* In fact the func will never get here but just in case */
    pthread_mutex_unlock(&mt->lock);
}

/*
 * cmp_expire - compare function of two timer structs
 *
 * a: single timer struct
 * 
 * b: single timer struct
 *
 * Returns: 
 * -1 if a < b;
 * 0 if a == b;
 * 1 if a > b
 * (similar to strcmp)
 */
int cmp_expire(single_timer_t* a, single_timer_t* b)
{
    struct timespec tmp;
    int ret = timespec_subtract(&tmp, &a->expire_time, &b->expire_time);
    if (ret == 1)
    {
        /* a - b is negative */
        /* a should be sorted before b */
        return -1;
    }
    if (tmp.tv_sec == 0 && tmp.tv_nsec == 0)
    {
        return 0;
    }
    return 1;
}

/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec)
    {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec >= SECOND) /* was > in the starter code */
    {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}

/*
 * timespec_add - add 2 timespec
 *
 * result: result struct
 *
 * x: timespec to be added
 * 
 * y: timespec to be added
 *
 * Returns: none (answer is passed via result)
 */
void timespec_add(struct timespec *result, struct timespec *x, struct timespec *y)
{
    result->tv_sec = x->tv_sec + y->tv_sec;
    result->tv_nsec = x->tv_nsec + y->tv_nsec;

    /* perform carry */
    if (result->tv_nsec >= SECOND)
    {
        uint64_t sec = result->tv_nsec / SECOND;
        result->tv_nsec -= SECOND * sec;
        result->tv_sec += sec;
    }
}

/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    chilog(TRACE, "init timer");
    pthread_mutex_init(&mt->lock, NULL);
    pthread_mutex_init(&mt->list_lock, NULL);
    pthread_cond_init(&mt->cv_list_update, NULL);

    mt->num_timers = num_timers;
    mt->termed = false;
    mt->single_timers = calloc(num_timers, sizeof(single_timer_t*));
    mt->active_timers = NULL;

    if (mt->single_timers == NULL)
    {
        return CHITCP_ENOMEM;
    }

    for (int id = 0; id < num_timers; id++)
    {
        mt->single_timers[id] = calloc(1, sizeof(single_timer_t));

        if (mt->single_timers[id] == NULL)
        {
            return CHITCP_EINIT;
        }

        mt->single_timers[id]->id = id;
        mt->single_timers[id]->active = false;
        mt->single_timers[id]->num_timeouts = 0;

        /* set the timer names for debug */
        if (id == 0) mt_set_timer_name(mt, id, "retrans timer");
        if (id == 1) mt_set_timer_name(mt, id, "persist timer");
    }

    timer_worker_args_t *wa;
    wa = calloc(1, sizeof(timer_worker_args_t));
    wa->mt = mt;

    if (pthread_create(&mt->thread, NULL, thread_timers, wa) != 0)
    {
        return CHITCP_ETHREAD;
    }


    return CHITCP_OK;
}


/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    chilog(TRACE, "free timer");

    /* cancel and join the timer thread that is running */
    mt->termed = true;
    int s = pthread_cancel(mt->thread);
    chilog(TRACE, "joining thread");
    pthread_join(mt->thread, NULL);

    /* then frees everything declared in multitimer struct */
    for (int id = 0; id < mt->num_timers; id++)
    {
        free(mt->single_timers[id]);
    }
    free(mt->single_timers);

    pthread_mutex_destroy(&mt->lock);
    pthread_mutex_destroy(&mt->list_lock);
    pthread_cond_destroy(&mt->cv_list_update);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{

    if (id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }

    *timer = mt->single_timers[id];

    return CHITCP_OK;
}

/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void* callback_args)
{
    chilog(TRACE, "set timer");

    /* first fill in the info */
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL)
    {
        return CHITCP_EINVAL;
    }
    if (timer->active)
    {
        return CHITCP_EINVAL;
    }
    timer->active = true;
    timer->callback = callback;
    timer->callback_args = callback_args;

    /* set the expire time */
    struct timespec now, tmp;
    clock_gettime(CLOCK_REALTIME, &now);
    tmp.tv_sec = timeout / SECOND;
    tmp.tv_nsec = timeout % SECOND;
    timespec_add(&timer->expire_time, &now, &tmp);

    int signal = 0;
    if (mt->active_timers == NULL || cmp_expire(timer, mt->active_timers) < 0)
        signal = 1;

    /* then add it to the list according to expire time */
    pthread_mutex_lock(&mt->list_lock);
    LL_INSERT_INORDER(mt->active_timers, timer, cmp_expire);
    pthread_mutex_unlock(&mt->list_lock);

    /* trigger condition variable if it is sorted to 1st element in list */
    if (signal)
    {
        pthread_cond_signal(&mt->cv_list_update);
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    chilog(TRACE, "cancel timer");


    single_timer_t *timer, *tmp;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL)
    {
        return CHITCP_EINVAL;
    }
    if (!timer->active)
    {
        return CHITCP_EINVAL;
    }
    timer->active = false;

    timer->callback = NULL;
    timer->callback_args = NULL;
    timer->expire_time.tv_sec = 0;
    timer->expire_time.tv_nsec = 0;

    int signal = 0;
    if (timer == mt->active_timers)
        signal = 1;

    /* remove it from the active_timers list */
    pthread_mutex_lock(&mt->list_lock);
    LL_DELETE(mt->active_timers, timer);
    pthread_mutex_unlock(&mt->list_lock);

    /* If this is the first timer in the list (i.e. timer thread is
     * blocking on it), you must also signal the thread */
    if (signal)
    {
        pthread_cond_signal(&mt->cv_list_update);
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    /* This is only used by init for debug
     * so no lock applied */
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL)
    {
        return CHITCP_EINVAL;
    }
    strcpy(timer->name, name);
    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active)
    {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;

        timespec_subtract(&diff, &timer->expire_time, &now);

        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    }
    else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{

    for (int id = 0; id < mt->num_timers; id++)
    {
        single_timer_t *curr_timer = mt->single_timers[id];
        if (!curr_timer->active && active_only) continue;
        mt_chilog_single_timer(level, curr_timer);
    }

    return CHITCP_OK;
}

/* See multitimer.h */
int mt_is_active(multi_timer_t *mt, uint16_t id)
{
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL)
    {
        return CHITCP_EINVAL;
    }

    if (timer->active)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
