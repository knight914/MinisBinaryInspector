#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <objc/runtime.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import <unistd.h>
#import "MachO.h"

static NSString *ReadMetadata(NSURL *url) {
    if (!url.isFileURL || !url.fileSystemRepresentation) return @"Expected a local file URL.";
    int fd = open(url.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return @"Could not open the selected file for reading.";
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 4 || (uint64_t)info.st_size > MBI_MAX_BYTES) {
        close(fd);
        return @"Select a regular Mach-O file between 4 bytes and 256 MiB.";
    }
    size_t length = (size_t)info.st_size;
    const uint8_t *bytes = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (bytes == MAP_FAILED) { close(fd); return @"Could not map the selected file for read-only inspection."; }
    struct stat after;
    BOOL stable = fstat(fd, &after) == 0 && after.st_dev == info.st_dev &&
        after.st_ino == info.st_ino && after.st_size == info.st_size && after.st_mtime == info.st_mtime;
    close(fd);
    MBIReport report;
    const char *error = stable ? MBIParse(bytes, length, &report) : "File changed while opening";
    munmap((void *)bytes, length);
    if (error) return [NSString stringWithFormat:@"Inspection failed: %s.", error];

    NSMutableString *text = [NSMutableString stringWithFormat:@"%@ · %llu bytes\n",
        report.fat ? (report.fat64 ? @"Universal (fat64)" : @"Universal (fat32)") : @"Thin Mach-O",
        (unsigned long long)length];
    if (report.fat) [text appendFormat:@"Universal table: %@-endian\n", report.little ? @"little" : @"big"];
    for (unsigned i = 0; i < report.count; ++i) {
        const MBISlice *s = &report.slices[i];
        [text appendFormat:@"\nSlice %u · %u-bit · %@-endian\nOffset %llu · Size %llu\nCPU 0x%08x · Subtype 0x%08x\nFile type 0x%08x · Flags 0x%08x\nLoad commands: %u (%u bytes)\n",
            i+1, s->wide ? 64u : 32u, s->little ? @"little" : @"big",
            (unsigned long long)s->offset, (unsigned long long)s->size,
            s->cpu, s->subtype, s->filetype, s->flags, s->commandCount, s->commandBytes];
        for (unsigned j = 0; j < s->commandCount && j < MBI_PREVIEW; ++j)
            [text appendFormat:@"  %u. 0x%08x (%u bytes)\n", j+1, s->preview[j].kind, s->preview[j].size];
        if (s->commandCount > MBI_PREVIEW)
            [text appendFormat:@"  … %u more\n", s->commandCount - MBI_PREVIEW];
    }
    return text;
}

@interface MBIInspectorController : UIViewController <UIDocumentPickerDelegate>
@property(nonatomic, strong) UITextView *output;
@property(nonatomic, strong) UIBarButtonItem *choose;
@property(nonatomic) BOOL busy;
@end

@implementation MBIInspectorController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Binary Inspector";
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(closeInspector)];
    self.choose = [[UIBarButtonItem alloc] initWithTitle:@"Choose File…" style:UIBarButtonItemStylePlain
        target:self action:@selector(chooseFile)];
    self.navigationItem.rightBarButtonItem = self.choose;
    self.output = [[UITextView alloc] init];
    self.output.editable = NO;
    self.output.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    self.output.adjustsFontForContentSizeCategory = YES;
    self.output.text = @"Choose a Mach-O file to inspect its headers and load-command metadata. The file will not be modified or executed.";
    self.output.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.output];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.output.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [self.output.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [self.output.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [self.output.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor]
    ]];
}
- (void)closeInspector { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)chooseFile {
    if (self.busy || self.presentedViewController) return;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[UTTypeData] asCopy:NO];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}
- (void)documentPicker:(UIDocumentPickerViewController *)picker didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    (void)picker;
    NSURL *url = urls.firstObject;
    if (!url || self.busy) return;
    self.busy = YES;
    self.choose.enabled = NO;
    self.output.text = @"Reading metadata…";
    __weak MBIInspectorController *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            BOOL scoped = [url startAccessingSecurityScopedResource];
            NSFileCoordinator *coordinator = [[NSFileCoordinator alloc] initWithFilePresenter:nil];
            __block NSString *result = nil;
            [coordinator coordinateReadingItemAtURL:url options:0 error:NULL byAccessor:^(NSURL *localURL) {
                result = ReadMetadata(localURL);
            }];
            if (scoped) [url stopAccessingSecurityScopedResource];
            dispatch_async(dispatch_get_main_queue(), ^{
                MBIInspectorController *controller = weakSelf;
                controller.output.text = result ?: @"The file provider could not make this file available.";
                [controller.output setContentOffset:CGPointZero animated:NO];
                controller.busy = NO;
                controller.choose.enabled = YES;
            });
        }
    });
}
@end

@interface MBIEntry : NSObject
- (void)openInspector:(UILongPressGestureRecognizer *)gesture;
@end
@implementation MBIEntry
- (void)openInspector:(UILongPressGestureRecognizer *)gesture {
    UIWindow *window = (UIWindow *)gesture.view;
    if (gesture.state != UIGestureRecognizerStateBegan || !window.isKeyWindow ||
        window.windowScene.activationState != UISceneActivationStateForegroundActive) return;
    UIViewController *root = window.rootViewController;
    if (!root || root.presentedViewController || root.isBeingDismissed || root.isBeingPresented) return;
    UINavigationController *navigation = [[UINavigationController alloc]
        initWithRootViewController:[[MBIInspectorController alloc] init]];
    navigation.modalPresentationStyle = UIModalPresentationFormSheet;
    [root presentViewController:navigation animated:YES completion:nil];
}
@end

static void Attach(UIWindow *window) {
    static char marker;
    static MBIEntry *entry;
    if (![window isKindOfClass:UIWindow.class] || !window.isKeyWindow || !window.windowScene ||
        window.windowLevel != UIWindowLevelNormal || objc_getAssociatedObject(window, &marker)) return;
    if (!entry) entry = [[MBIEntry alloc] init];
    UILongPressGestureRecognizer *hold = [[UILongPressGestureRecognizer alloc]
        initWithTarget:entry action:@selector(openInspector:)];
    hold.numberOfTouchesRequired = 3;
    hold.minimumPressDuration = 1.2;
    hold.cancelsTouchesInView = NO;
    hold.delaysTouchesBegan = NO;
    hold.delaysTouchesEnded = NO;
    [window addGestureRecognizer:hold];
    objc_setAssociatedObject(window, &marker, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

__attribute__((constructor)) static void StartInspector(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.aztut.app"]) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            [NSNotificationCenter.defaultCenter addObserverForName:UIWindowDidBecomeKeyNotification
                object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
                    Attach(note.object);
                }];
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes)
                if ([scene isKindOfClass:UIWindowScene.class])
                    for (UIWindow *window in ((UIWindowScene *)scene).windows) Attach(window);
        });
    }
}
