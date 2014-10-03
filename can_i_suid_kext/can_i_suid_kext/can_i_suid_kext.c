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
 * can_i_suid.c
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

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <kern/task.h>
#include <sys/proc.h>
#include <kern/thread.h>
#include <kern/locks.h>
#include <kern/clock.h>
#include <sys/vm.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <Availability.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <libkern/OSMalloc.h>
#include <sys/kauth.h>

#include "userland_comms.h"
#include "shared.h"
#include "logging.h"
#include "config.h"

#define S_ISUID         0004000         /* [XSI] set user id on execution */
#define S_ISGID         0002000         /* [XSI] set group id on execution */

extern int g_connection_to_userland;
extern struct to_userland_queue g_to_queue;
extern struct from_userland_queue g_from_queue;

int g_comms_active = 0;

static OSMallocTag g_osmalloc_tag;

SLIST_HEAD(whitelist_slist, whitelist_entry);
static struct whitelist_slist g_whitelist;

struct whitelist_entry
{
    struct vnode *vnode;
    uid_t uid;
    SLIST_ENTRY(whitelist_entry) entries;
};

#pragma mark -
#pragma mark TrustedBSD Hooks

static int can_i_suid_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct label *label, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);

/* the hooks we are interested in */
static struct mac_policy_ops can_i_suid_ops =
{
    .mpo_vnode_check_exec = can_i_suid_vnode_check_exec
};

mac_policy_handle_t can_i_suid_handle;

static struct mac_policy_conf can_i_suid_policy_conf = {
    .mpc_name            = "can_I_suid",
    .mpc_fullname        = "Can I SUID Kernel Driver",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &can_i_suid_ops,
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK, /* NOTE: this allows to unload, good idea to remove in release */
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

/* NOTE: this function prototype changed from 10.8 to 10.9 and also 10.10
 *       so it needs to be specific for each version and use each SDK.
 *       there are other functions that suffered the same fate
 *       this is probably the main reason why Apple is closing TrustedBSD access
 *
 * A return value of 0 means access is granted or check deferred to next hook.
 * A value higher than zero means access is refused right away.
 */
static int
can_i_suid_vnode_check_exec(kauth_cred_t cred,
                            struct vnode *vp,
                            struct label *label,
                            struct label *execlabel,
                            struct componentname *cnp,
                            u_int *csflags,
                            void *macpolicyattr,
                            size_t macpolicyattrlen)
{
    /* NOTE:
     * we can't start the devices when we start the driver because it's too early (kernel panic!!!)
     * so we wait before the first process is launched to start
     */
    if (g_comms_active == 0)
    {
        SLIST_INIT(&g_whitelist);
        start_comms();
        g_comms_active++;
    }

    struct vnode_attr vap = {0};
    vfs_context_t context = vfs_context_create(NULL);
    if (context == NULL)
    {
        ERROR_MSG("Failed to create context.");
        return 0;
    }
    /* initialize the structure fields we are interested in */
    VATTR_INIT(&vap);
    VATTR_WANTED(&vap, va_mode);
    if ( vnode_getattr(vp, &vap, context) != 0 )
    {
        ERROR_MSG("Failed to get vnode attributes.");
        /* XXX: what action here???? */
    }
    vfs_context_rele(context);
    
    /* verify if binary has any SUID bit set */
    if (vap.va_mode & S_ISUID || vap.va_mode & S_ISGID)
    {
        /* retrieve the UID of the process so we whitelist per user */
        uid_t target_uid = kauth_getuid();
        
        struct whitelist_entry *entry = NULL;
        /* verify if this vnode is whitelisted */
        SLIST_FOREACH(entry, &g_whitelist, entries)
        {
            /* verify that the vnodes match and also the UID because we want whitelist per user and not global */
            if (entry->vnode == vp && entry->uid == kauth_getuid())
            {
                /* there's only whitelisting so let it proceed */
                return 0;
            }
        }
        
        struct userland_event event = {0};
        
        int pathbuff_len = sizeof(event.path);
        
        if ( vn_getpath(vp, event.path, &pathbuff_len) != 0 )
        {
            ERROR_MSG("Can't build path to vnode.");
            /* XXX: what action here???? */
        }
        
        /* XXX: gather more information about both processes? */
        proc_t target_proc = current_proc();
        if (target_proc == (struct proc *)0)
        {
            ERROR_MSG("Couldn't find process for task!");
            return 0;
        }
        /* retrieve parent information */
        /* unfortunately there's no function to get the vnode from a proc_t without some disassembly magic */
        /* a new function for this was introduced in Yosemite */
        pid_t parent_pid = proc_ppid(target_proc);
        proc_name(parent_pid, event.parent_name, sizeof(event.parent_name));
        /* notify userland */
        DEBUG_MSG("Trying to execute suid binary %s with parent %s.", event.path, event.parent_name);
        event.action = kDenySuid;
        event.pid = proc_pid(target_proc);
        event.ppid = parent_pid;
        event.uid = target_uid;
        /* parent info */
        /* XXX: not sure if there's an easier way to get this info */
        proc_t parent_proc = proc_find(parent_pid);
        if (parent_proc != (struct proc*)0)
        {
            kauth_cred_t cred = kauth_cred_proc_ref(parent_proc);
            if ( IS_VALID_CRED(cred) != 0 )
            {
                /* retrieve parent UID */
                event.puid = kauth_cred_getuid(cred);
                /* release references */
                kauth_cred_unref(&cred);
            }
            /* release references */
            proc_rele(parent_proc);
        }
        /* if we have a connection with userland we should wait for response */
        if (g_connection_to_userland)
        {
            event.active = 1;
            /*  send request to userland */
            queue_userland_data(&event);
            /*
             * now wait for response - if we don't get a response default is to deny access
             * unless we are still not connected to userland
             */
            struct timespec waittime = {0};
            int crap;
            waittime.tv_sec  = 0;
            waittime.tv_nsec = USERLAND_RESPONSE_PERIOD;
            int attempts = 0;
            enum action_t auth_status = -1;
            while (1)
            {
                msleep(&crap, NULL, PUSER, "suid", &waittime);
                if ( get_authorization_status(event.pid, &auth_status) == 0 )
                {
                    ERROR_MSG("Found return result!");
                    if (auth_status == kWhitelistSuid)
                    {
                        /* add to the list */
                        struct whitelist_entry *new_entry = OSMalloc(sizeof(struct whitelist_entry), g_osmalloc_tag);
                        if (new_entry != NULL)
                        {
                            new_entry->vnode = vp;
                            new_entry->uid = target_uid;
                            SLIST_INSERT_HEAD(&g_whitelist, new_entry, entries);
                        }
                        /* set the status to allow because whitelist means always access */
                        auth_status = kAllowSuid;
                    }
                    return auth_status;
                }
                /* timeout exceed return default value */
                if (attempts > USERLAND_TIMEOUT_COUNT)
                {
                    DEBUG_MSG("Return result for PID %d not found.", event.pid);
                    return DEFAULT_POLICY;
                }
                attempts++;
            }
        }
        /* userland daemon still not connected so we take note but authorize anyways */
        else
        {
            /* just queue internally to send when connected */
            enqueue_to_event(&g_to_queue, &event);
            /* always authorize */
            return 0;
        }
    }
    return 0;
}

#pragma mark -
#pragma mark TrustedBSD Start and stop functions

kern_return_t can_i_suid_kext_start(kmod_info_t * ki, void *d);
kern_return_t can_i_suid_kext_stop(kmod_info_t *ki, void *d);

kern_return_t can_i_suid_kext_start(kmod_info_t * ki, void *d)
{
    g_osmalloc_tag = OSMalloc_Tagalloc(BUNDLE_ID, OSMT_DEFAULT);
    if (g_osmalloc_tag == 0)
    {
        ERROR_MSG("Failed to initialize OSMalloc tag.");
        return KERN_FAILURE;
    }

    if ( mac_policy_register(&can_i_suid_policy_conf, &can_i_suid_handle, d) != KERN_SUCCESS )
    {
        ERROR_MSG("Failed to start Can I SUID TrustedBSD module!");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

kern_return_t can_i_suid_kext_stop(kmod_info_t *ki, void *d)
{
    kern_return_t kr = 0;
    if ( stop_comms() != KERN_SUCCESS )
    {
        return KERN_FAILURE;
    }
    /* cleanup the whitelist */
    struct whitelist_entry *entry = NULL;
    struct whitelist_entry *next_entry = NULL;
    SLIST_FOREACH_SAFE(entry, &g_whitelist, entries, next_entry)
    {
        SLIST_REMOVE(&g_whitelist, entry, whitelist_entry, entries);
        OSFree(entry, sizeof(struct whitelist_entry), g_osmalloc_tag);
    }
    if (g_osmalloc_tag)
    {
        OSMalloc_Tagfree(g_osmalloc_tag);
    }
    
    if ( (kr = mac_policy_unregister(can_i_suid_handle)) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to unload CAN I SUID TrustedBSD module: %d.", kr);
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}
