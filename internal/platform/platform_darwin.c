//go:build darwin

#include <os/log.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

extern void sefkoGoWillSleep(void);

static os_log_t audit_log;
static os_log_t agent_log;

void sefko_log_init(void) {
	audit_log = os_log_create("io.nkl.sefko", "audit");
	agent_log = os_log_create("io.nkl.sefko", "agent");
}

void sefko_log(int level, const char *msg) {
	switch (level) {
	case 0:
		os_log_with_type(audit_log, OS_LOG_TYPE_INFO, "%{public}s", msg);
		break;
	case 1:
		os_log_with_type(agent_log, OS_LOG_TYPE_INFO, "%{public}s", msg);
		break;
	default:
		os_log_with_type(agent_log, OS_LOG_TYPE_ERROR, "%{public}s", msg);
		break;
	}
}

static io_connect_t root_port;
static IONotificationPortRef notify_port;
static io_object_t notifier;
static CFRunLoopRef power_loop;
static _Atomic int stop_requested;

static void power_callback(void *ref, io_service_t service, natural_t type, void *arg) {
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(root_port, (long)arg);
		break;
	case kIOMessageSystemWillSleep:
		// Wipe before acknowledging, so secrets are gone before the system sleeps.
		sefkoGoWillSleep();
		IOAllowPowerChange(root_port, (long)arg);
		break;
	default:
		break;
	}
}

int sefko_power_register(void) {
	root_port = IORegisterForSystemPower(NULL, &notify_port, power_callback, &notifier);
	if (root_port == MACH_PORT_NULL) {
		return -1;
	}
	stop_requested = 0;
	power_loop = CFRunLoopGetCurrent();
	CFRunLoopAddSource(power_loop, IONotificationPortGetRunLoopSource(notify_port), kCFRunLoopDefaultMode);
	return 0;
}

void sefko_power_run(void) {
	// Poll the flag so a stop that arrives before the loop starts is not lost.
	while (!stop_requested) {
		CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, false);
	}
	CFRunLoopRemoveSource(power_loop, IONotificationPortGetRunLoopSource(notify_port), kCFRunLoopDefaultMode);
	IODeregisterForSystemPower(&notifier);
	IOServiceClose(root_port);
	IONotificationPortDestroy(notify_port);
	power_loop = NULL;
}

void sefko_power_stop(void) {
	stop_requested = 1;
	if (power_loop != NULL) {
		CFRunLoopStop(power_loop);
	}
}
