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
 * config.h
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

#ifndef can_i_suid_kext_config_h
#define can_i_suid_kext_config_h

/* the number of *nanosecs* to sleep between checking if userland sent response */
#define USERLAND_RESPONSE_PERIOD                        400000
/* the number of attempts before timeout waiting for userland  response */
/* total timeout = USERLAND_TIMEOUT_COUNT * USERLAND_RESPONSE_PERIOD */
#define USERLAND_TIMEOUT_COUNT                         12500

/* queues sizes */
#define TO_QUEUE_SIZE 100
#define FROM_QUEUE_SIZE 10

/* 0 - allow, 1 - deny */
/* used when we can't get userland response or errors */
#define DEFAULT_POLICY  1

#endif
