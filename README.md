Can I SUID - A TrustedBSD module to control SUID binaries execution

Copyright (c) fG!, 2014 - reverser@put.as - http://reverse.put.as

This is a TrustedBSD module to control execution of binaries with suid bit set.

The idea came from nemo's shellshock exploitation leveraging VMWare Fusion's suid binaries.

It is split between a TrustedBSD policy kernel extension and a userland application (a menubar item). The kernel extension detects and controls the binaries execution, and the application receives the kernel notifications and asks the user to take a decision on the binary to be executed.

The execution of the suid binary is blocked until a user decision is made or a timeout is reached (in this case the default decision is to deny execution). NSAlert is used for user  decision, which is not pretty but my Cocoa skills are crap (you are definitely welcome to improve this, something like Little Snitch requests).

I'm still experimenting with the workflow. Some binaries such as login and ps could be whitelisted because every time you start them you get a request. That might be a bit annoying.

Because the driver can be loaded very early in the boot process (this trick unfortunately is not available anymore in Yosemite) it will only notify the userland application of any suid binary that executed before userland connected. From my tests no suid binaries are executed in the boot process so this can provide you a forensics tip.

This sample code *only* works in Mavericks (tested with 10.9.2 and 10.9.5). The reason is due to changing TrustedBSD hooks prototypes between Mountain Lion, Mavericks and Yosemite. Each version needs specific prototypes and must be compiled with the correspondent SDK. Can't do much here :-(. For some weird reason the userland application deployment target must be 10.7 or lower else the alerts do not show up. Maybe because the sample code I used is too old?

The early boot startup is achieved by using AppleSecurityExtension in the driver plist and also using com.apple in the bundle identifier (check the plist). This is the reason why this trick doesn't work anymore in Yosemite because of the strict code signature checks. For Mavericks (and Mountain Lion?) you still need a valid code signing certificate with the kernel extension enabled.
The userland application should be installed as a login item.

Communication between kernel and userland is implemented using kernel control interface. This is ok for low volumes of data. For high volumes it has a bug and starts losing data with error 55.

The userland application is based on code from Vadim Shpakovski - http://blog.shpakovski.com/2011/07/cocoa-popup-window-in-status-bar.html. Icons from images.google.com.

Feel free to improve and submit pull requests. The Cocoa part definitely needs some love :-).

Enjoy,

fG!
