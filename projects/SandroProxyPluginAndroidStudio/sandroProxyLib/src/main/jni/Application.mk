APP_OPTIM := release
APP_ABI := armeabi-v7a x86

ifeq ($(TARGET_ARCH),x86)
APP_CFLAGS := -DX86_ARCH
endif

APP_PLATFORM := android-8
