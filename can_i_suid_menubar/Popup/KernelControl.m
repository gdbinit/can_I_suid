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
 * KernelControl.c
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

#import "KernelControl.h"

static void kernel_notifications(void);

@implementation KernelControl

- (id)init
{
    self = [super init];
    if (self != nil)
    {
    }
    
    return self;
}

/* function responsible to connect to kernel control socket */
- (int)startKernelControl
{
    _sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (_sock < 0)
    {
        ERROR_MSG("Failed to create kernel control socket. Error %d (%s).", errno, strerror(errno));
        return -1;
    }
    
    /* the control ID is dynamically generated so we must obtain sc_id using ioctl */
    memset(&_ctl_info, 0, sizeof(_ctl_info));
    strncpy(_ctl_info.ctl_name, BUNDLE_ID, MAX_KCTL_NAME);
    _ctl_info.ctl_name[MAX_KCTL_NAME-1] = '\0';
    if ( ioctl(_sock, CTLIOCGINFO, &_ctl_info) == -1 )
    {
        ERROR_MSG("Failed to retrieve bundle information! Error %d (%s).", errno, strerror(errno));
        /* if we can't get the bundle info it means the kernel socket is not up, */
        /* so close the socket else check above will be always true */
        close(_sock);
        _sock = -1;
        return -1;
    }
    _sc.sc_len = sizeof(struct sockaddr_ctl);
    _sc.sc_family = AF_SYSTEM;
    _sc.ss_sysaddr = AF_SYS_CONTROL;
    _sc.sc_id = _ctl_info.ctl_id;
    _sc.sc_unit = 0;
    if ( connect(_sock, (struct sockaddr*)&_sc, sizeof(_sc)) )
    {
        ERROR_MSG("Failed to connect to kernel control socket! Error %d (%s).", errno, strerror(errno));
        return -1;
    }
    
    /* create the handler to act when data is received on the socket */
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_source_t ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _sock, 0, queue);
    dispatch_source_set_event_handler(ds, ^{
        [self kernelNotifications];
    });
    dispatch_resume(ds);

    return 0;
}

/* the function responsible for reading events from the kernel and replying */
-(void)kernelNotifications
{
    ssize_t n = 0;
    struct userland_event data = {0};
    /* we managed to read something, check what it is */
    n = recv(_sock, &data, sizeof(struct userland_event), 0);
    if (n < 0)
    {
        ERROR_MSG("Recv error.");
    }
    else if (n < sizeof(struct userland_event))
    {
        ERROR_MSG("Received smaller buffer than expected from kernel.");
    }
    else
    {
        /*
         * these are the events that occurred before the GUI is connected
         * there was no action over these so we just display them as notifications when we receive that data from the kernel
         */
        if  (data.active == 0)
        {
            NSUserNotification *notification = [[NSUserNotification alloc] init];
            notification.title = @"SUID notification";
            notification.hasActionButton = NO;
            notification.informativeText = [NSString stringWithFormat:@"Binary %s with PID %d and UID %d.\rParent %s with PID %d and UID %d.",
                                            data.path, data.pid, data.uid, data.parent_name, data.ppid, data.puid];
            
            [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
        }
        else
        {
            /* NSAlert is recommended to be displayed in the main thread so use it */
            dispatch_sync(dispatch_get_main_queue(), ^{
                NSAlert *alert = [[NSAlert alloc] init];
                [alert addButtonWithTitle:@"Allow"];
                [alert addButtonWithTitle:@"Deny"];
                [alert addButtonWithTitle:@"Whitelist"];
                [alert setMessageText:@"SUID Execution"];
                NSString *informativeText = [NSString stringWithFormat:@"Binary %s with PID %d and UID %d.\rParent %s with PID %d and UID %d.",
                                             data.path, data.pid, data.uid, data.parent_name, data.ppid, data.puid];
                [alert setInformativeText:informativeText];
                [alert setAlertStyle:NSCriticalAlertStyle];
                NSInteger buttonPressed = [alert runModal];
                
                int operation = 0;
                struct userland_event reply = {0};
                reply.pid = data.pid;
                /* allow button */
                if (buttonPressed == NSAlertFirstButtonReturn)
                {
                    reply.action = kAllowSuid;
                }
                /* deny button */
                else if (buttonPressed ==  NSAlertSecondButtonReturn)
                {
                    reply.action = kDenySuid;
                }
                else if (buttonPressed == NSAlertThirdButtonReturn)
                {
                    reply.action = kWhitelistSuid;
                }
                /* try to send to kernel - if it fails kernel will timeout and assume the default action value */
                if ( setsockopt(_sock, SYSPROTO_CONTROL, operation, (void*)&reply, (socklen_t)sizeof(struct userland_event)) )
                {
                    ERROR_MSG("Failed to send response via kernel control! Error: %d (%s).", errno, strerror(errno));
                }
            });
        }
    }
}

@end


