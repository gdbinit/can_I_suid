#import "MenubarController.h"
#import "PanelController.h"
#import "KernelControl.h"

@interface ApplicationDelegate : NSObject <NSApplicationDelegate, PanelControllerDelegate, NSUserNotificationCenterDelegate>

@property (nonatomic, strong) MenubarController *menubarController;
@property (nonatomic, strong, readonly) PanelController *panelController;
@property (nonatomic, strong) KernelControl *kernelControl;

- (IBAction)togglePanel:(id)sender;

@end
