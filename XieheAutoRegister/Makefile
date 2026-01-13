THEOS_DEVICE_IP = 192.168.5.106
THEOS_DEVICE_PORT = 2222

INSTALL_TARGET_PROCESSES = 北京协和医院

ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = XieheAutoRegister

XieheAutoRegister_FILES = Tweak.xm PreciseGCDTimer.m XHPatientDetailDisplayController.m XHScheduleListController.m \
	XieheSettings.m XieheSettingsViewController.m
XieheAutoRegister_CFLAGS = -fobjc-arc
XieheAutoRegister_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 'hundsun_health_xiehe'" || true
