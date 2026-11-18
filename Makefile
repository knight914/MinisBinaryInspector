ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MinisBinaryInspector
MinisBinaryInspector_FILES = Inspector.m MachO.c
MinisBinaryInspector_OBJCFLAGS = -fobjc-arc
MinisBinaryInspector_FRAMEWORKS = UIKit Foundation UniformTypeIdentifiers

include $(THEOS_MAKE_PATH)/tweak.mk

ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
THEOS_PACKAGE_ARCH = iphoneos-arm64e
else
THEOS_PACKAGE_ARCH = iphoneos-arm64
endif
