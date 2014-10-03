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
 * userland_comms.h
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

#ifndef __can_i_suid__userland_comms__
#define __can_i_suid__userland_comms__

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/vnode.h>

#include "shared.h"

struct to_userland_queue {
    struct userland_event *queue;
    int count;
    int start;
    int size;
};

struct from_userland_queue {
    struct userland_event *queue;
    int count;
    int start;
    int size;
};

kern_return_t start_comms(void);
kern_return_t stop_comms(void);

void enqueue_to_event(struct to_userland_queue *queue, struct userland_event *event);
int dequeue_to_event(struct to_userland_queue *queue, struct userland_event *event);

kern_return_t queue_userland_data(struct userland_event *event);
kern_return_t queue_inactive_userland_data(void);

int get_authorization_status(pid_t pid, enum action_t *result);

#endif /* defined(__can_i_suid__userland_comms__) */
