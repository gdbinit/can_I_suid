//
//  logging.h
//  can_i_suid_menubar
//
//  Created by reverser on 02/10/14.
//
//

#ifndef can_i_suid_menubar_logging_h
#define can_i_suid_menubar_logging_h

#define ERROR_MSG(fmt, ...) NSLog(@"[ERROR] " fmt "\n", ## __VA_ARGS__)
#define DEBUG_MSG(fmt, ...) NSLog(@"[DEBUG] " fmt "\n", ##  __VA_ARGS__)

#endif
