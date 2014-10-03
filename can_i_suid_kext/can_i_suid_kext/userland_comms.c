/*
 *            (`-')  _ <-. (`-')_           _
 *  _         (OO ).-/    \( OO) )         (_)
 *  \-,-----. / ,---.  ,--./ ,--/          ,-(`-')
 *  |  .--./ | \ /`.\ |   \ |  |          | ( OO)
 *  /_) (`-') '-'|_.' ||  . '|  |)         |  |  )
 *  ||  |OO )(|  .-.  ||  |\    |         (|  |_/
 * (_'  '--'\ |  | |  ||  | \   |          |  |'->
 *   `-----' `--' `--'`--'  `--'          `--'
 * (`-').->             _     _(`-')
 * ( OO)_       .->    (_)   ( (OO ).->
 * (_)--\_) ,--.(,--.   ,-(`-')\    .'_
 * /    _ / |  | |(`-') | ( OO)'`'-..__)
 * \_..`--. |  | |(OO ) |  |  )|  |  ' |
 * .-._)   \|  | | |  \(|  |_/ |  |  / :
 * \       /\  '-'(_ .' |  |'->|  '-'  /
 * `-----'  `-----'    `--'   `------'
 *
 * Can I SUID - A TrustedBSD module to control SUID binaries execution
 *
 * userland_comms.c
 * Created by reverser on 02/10/14.
 *
 * Copyright (c) fG!, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "userland_comms.h"

#include <sys/systm.h>
#include <sys/conf.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/proc.h>
#include <kern/locks.h>
#include <sys/kern_control.h>
#include <sys/malloc.h>

#include "logging.h"
#include "config.h"

lck_grp_t *g_mutexes_grp;
lck_mtx_t *g_to_mutex;
lck_mtx_t *g_from_mutex;
int g_connection_to_userland;

struct to_userland_queue g_to_queue;
struct from_userland_queue g_from_queue;

static kern_return_t init_queues(struct to_userland_queue *to_queue, struct from_userland_queue *from_queue);
static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

static struct kcontrol_info
{
    int max_clients;
    kern_ctl_ref ctl_ref;
    u_int32_t client_unit;
    kern_ctl_ref client_ctl_ref;
    boolean_t kern_ctl_registered;
} g_kcontrol;

// described at Network Kernel Extensions Programming Guide
static struct kern_ctl_reg g_ctl_reg = {
    BUNDLE_ID,  /* use a reverse dns name which includes a name unique to your comany */
    0,				   	  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,					  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    0,                    /* no privileged access required to access this filter */
    0,					  /* use default send size buffer */
    0,                    /* Override receive buffer size */
    ctl_connect,		  /* Called when a connection request is accepted */
    ctl_disconnect,		  /* called when a connection becomes disconnected */
    NULL,				  /* ctl_send_func - handles data sent from the client to kernel control - not implemented */
    ctl_set,			  /* called when the user process makes the setsockopt call */
    NULL			 	  /* called when the user process makes the getsockopt call */
};

kern_return_t
start_comms(void)
{
    g_mutexes_grp = lck_grp_alloc_init("mutexes", LCK_GRP_ATTR_NULL);
    if (g_mutexes_grp == NULL)
    {
        ERROR_MSG("Can't initialize mutex group.");
        return KERN_FAILURE;
    }
    g_to_mutex = lck_mtx_alloc_init(g_mutexes_grp, LCK_ATTR_NULL);
    if (g_to_mutex == NULL)
    {
        ERROR_MSG("Can't initialize device mutex.");
        return KERN_FAILURE;
    }
    g_from_mutex = lck_mtx_alloc_init(g_mutexes_grp, LCK_ATTR_NULL);
    if (g_from_mutex == NULL)
    {
        ERROR_MSG("Can't initialize device mutex.");
        return KERN_FAILURE;
    }

    if ( init_queues(&g_to_queue, &g_from_queue) != KERN_SUCCESS )
    {
        ERROR_MSG("Can't initialize queues.");
        return KERN_FAILURE;
    }
    
    errno_t error = 0;
    // register the kernel control
    error = ctl_register(&g_ctl_reg, &g_kcontrol.ctl_ref);
    if (error == 0)
    {
        g_kcontrol.kern_ctl_registered = TRUE;
        return KERN_SUCCESS;
    }
    else
    {
        g_kcontrol.kern_ctl_registered = FALSE;
        ERROR_MSG("Failed to install kernel control!");
        return KERN_FAILURE;
    }
}

kern_return_t
stop_comms(void)
{
    /* can't unload kext if there are clients connected else it will lead to kernel panic */
    if (g_kcontrol.max_clients > 0)
    {
        return KERN_FAILURE;
    }
    errno_t error = 0;
    // remove kernel control
    error = ctl_deregister(g_kcontrol.ctl_ref);
    switch (error)
    {
        case 0:
        {
            return KERN_SUCCESS;
        }
        case EINVAL:
        {
            ERROR_MSG("The kernel control reference is invalid.");
            return KERN_FAILURE;
        }
        case EBUSY:
        {
            ERROR_MSG("The kernel control stil has clients attached.");
            return KERN_FAILURE;
        }
        default:
            return KERN_FAILURE;
    }
}

#pragma mark -
#pragma Queue functions

static kern_return_t
init_queues(struct to_userland_queue *to_queue, struct from_userland_queue *from_queue)
{
    if (to_queue == NULL || from_queue == NULL)
    {
        ERROR_MSG("Invalid argument.");
        return KERN_FAILURE;
    }
    
    lck_mtx_lock(g_to_mutex);
    to_queue->queue = _MALLOC(TO_QUEUE_SIZE*sizeof(struct userland_event), M_TEMP, M_ZERO | M_WAITOK);
    if (to_queue->queue == NULL)
    {
        ERROR_MSG("Error allocating queue memory!");
        lck_mtx_unlock(g_to_mutex);
        return KERN_FAILURE;
    }
    to_queue->size = TO_QUEUE_SIZE;
    to_queue->start = 0;
    to_queue->count = 0;
    lck_mtx_unlock(g_to_mutex);
    
    lck_mtx_lock(g_from_mutex);
    from_queue->queue = _MALLOC(FROM_QUEUE_SIZE*sizeof(struct userland_event), M_TEMP, M_ZERO | M_WAITOK);
    if (from_queue->queue == NULL)
    {
        ERROR_MSG("Error allocating queue memory!");
        lck_mtx_unlock(g_from_mutex);
        return KERN_FAILURE;
    }
    from_queue->size = FROM_QUEUE_SIZE;
    from_queue->start = 0;
    from_queue->count = 0;
    lck_mtx_unlock(g_from_mutex);

    return KERN_SUCCESS;
}

static void
terminate_queue(struct to_userland_queue *to_queue, struct from_userland_queue *from_queue)
{
    if (to_queue == NULL || from_queue == NULL)
    {
        ERROR_MSG("Invalid argument.");
        return;
    }
    
    lck_mtx_lock(g_to_mutex);
    if (to_queue->queue)
    {
        _FREE(to_queue->queue, M_TEMP);
    }
    to_queue->count = 0;
    to_queue->start = 0;
    to_queue->size = 0;
    lck_mtx_unlock(g_to_mutex);
    
    lck_mtx_lock(g_from_mutex);
    if (from_queue->queue)
    {
        _FREE(from_queue->queue, M_TEMP);
    }
    from_queue->count = 0;
    from_queue->start = 0;
    from_queue->size = 0;
    lck_mtx_unlock(g_from_mutex);
}

void
enqueue_to_event(struct to_userland_queue *queue, struct userland_event *event)
{
    if (queue == NULL || event == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return;
    }
    
    lck_mtx_lock(g_to_mutex);
    if (queue->size <= 0 || queue->queue == NULL)
    {
        lck_mtx_unlock(g_to_mutex);
        return;
    }
    int end = (queue->start + queue->count) % queue->size;
    queue->queue[end] = *event;
    if (queue->count == queue->size)
    {
        queue->start = (queue->start + 1) % queue->size;
    }
    else
    {
        ++ queue->count;
    }
    lck_mtx_unlock(g_to_mutex);
}

int
dequeue_to_event(struct to_userland_queue *queue, struct userland_event *event)
{
    if (queue == NULL || event == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 1;
    }
    
    lck_mtx_lock(g_to_mutex);
    if (queue->count == 0 || queue->size <= 0 || queue->queue == NULL)
    {
        lck_mtx_unlock(g_to_mutex);
        return 1;
    }
    *event = queue->queue[queue->start];
    queue->start = (queue->start + 1) % queue->size;
    -- queue->count;
    lck_mtx_unlock(g_to_mutex);
    return 0;
}

void
enqueue_from_event(struct from_userland_queue *queue, struct userland_event *event)
{
    if (queue == NULL || event == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return;
    }
    
    lck_mtx_lock(g_from_mutex);
    if (queue->size <= 0 || queue->queue == NULL)
    {
        lck_mtx_unlock(g_from_mutex);
        return;
    }
    int end = (queue->start + queue->count) % queue->size;
    queue->queue[end] = *event;
    if (queue->count == queue->size)
    {
        queue->start = (queue->start + 1) % queue->size;
    }
    else
    {
        ++ queue->count;
    }
    lck_mtx_unlock(g_from_mutex);
}

int
dequeue_from_event(struct from_userland_queue *queue, struct userland_event *event)
{
    if (queue == NULL || event == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 1;
    }
    
    lck_mtx_lock(g_from_mutex);
    if (queue->count == 0 || queue->size <= 0 || queue->queue == NULL)
    {
        lck_mtx_unlock(g_from_mutex);
        return 1;
    }
    *event = queue->queue[queue->start];
    queue->start = (queue->start + 1) % queue->size;
    -- queue->count;
    lck_mtx_unlock(g_from_mutex);
    return 0;
}

#pragma mark -
#pragma mark Kernel control functions

/*
 * called when a client connects to the socket
 * we need to store some info to use later
 */
static int
ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    /* XXX: Client authentication should be added here :-) */
    
    /* we only accept a single client */
    if (g_kcontrol.max_clients > 0)
    {
        return EBUSY;
    }
    g_kcontrol.max_clients++;
    // store the unit id and ctl_ref of the client that connected
    // we will need these to queue data to userland
    g_kcontrol.client_unit = sac->sc_unit;
    g_kcontrol.client_ctl_ref = ctl_ref;
    g_connection_to_userland = 1;
    /*
     * send any SUID that happened before the client connected
     * these are only displayed as notifications since we can't act over them
     */
    errno_t error = 0;
    DEBUG_MSG("Number of events in to userland queue: %d.", g_to_queue.count);
    while (g_to_queue.count != 0)
    {
        struct userland_event tmp = {0};
        dequeue_to_event(&g_to_queue, &tmp);
        error = ctl_enqueuedata(g_kcontrol.client_ctl_ref, g_kcontrol.client_unit, &tmp, sizeof(struct userland_event), CTL_DATA_EOR);
        /* XXX: in case of error we should add back to the queue 
         *      problem is that this would generate a loop
         *      queue or not depending on the error type?
         */
        if (error)
        {
            ERROR_MSG("Failed to send inactive event with error: %d.", error);
        }
    }
    return 0;
}

/*
 * and when client disconnects
 */
static errno_t
ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    // reset some vars
    g_kcontrol.max_clients = 0;
    g_kcontrol.client_unit = 0;
    g_kcontrol.client_ctl_ref = NULL;
    g_connection_to_userland = 0;
    return 0;
}

/*
 * receive data from userland to kernel
 */
static int
ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int error = 0;
    if (len == 0 || data == NULL)
    {
        ERROR_MSG("Invalid reply event?");
        return EINVAL;
    }
    
    /* XXX: add some kind of error checking to the input data? */
    switch (opt)
    {
        case 0:
        {
            struct userland_event *reply = (struct userland_event*)data;
            enqueue_from_event(&g_from_queue, reply);
            break;
        }
        default:
            error = ENOTSUP;
            break;
    }
    return error;
}

#pragma mark -

/*
 * queue data so userland can read
 * this is used for the events when userland is already connected
 */
kern_return_t
queue_userland_data(struct userland_event *event)
{
    errno_t error = 0;
    if (g_kcontrol.client_ctl_ref == NULL)
    {
        ERROR_MSG("No client reference available.");
        return KERN_FAILURE;
    }
    
    error = ctl_enqueuedata(g_kcontrol.client_ctl_ref, g_kcontrol.client_unit, event, sizeof(struct userland_event), CTL_DATA_EOR);
    if (error)
    {
        ERROR_MSG("ctl_enqueuedata failed with error: %d", error);
    }
    return error;
}

/* 
 * iterate the queue and see if we have a response from the given PID
 * XXX: not very efficient search
 *      since the kernel blocks we don't really need to search the whole queue
 *      but it's expected to have a single event
 */
int
get_authorization_status(pid_t pid, enum action_t *result)
{
    if (g_from_queue.size != FROM_QUEUE_SIZE)
    {
        ERROR_MSG("Something wrong with from userland queue.");
        return -1;
    }
    
    for (int i = 0; i < FROM_QUEUE_SIZE; i++)
    {
        struct userland_event event = g_from_queue.queue[i];
        if (event.pid == pid)
        {
            *result = event.action;
            dequeue_from_event(&g_from_queue, &event);
            return 0;
        }
    }
    return -1;
}
