# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,k
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

APP_ABI := armeabi armeabi-v7a

include $(CLEAR_VARS)
LOCAL_MODULE := sodium

ifeq ($(TARGET_ARCH_ABI), armeabi)
	LOCAL_SRC_FILES := /home/gerard/pau/libsodium/libsodium-android-arm/lib/libsodium.a
endif

ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
	LOCAL_C_INCLUDES += /home/gerard/pau/libsodium/libsodium-android-armv7/lib/libsodium.a
endif

include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := testjni
LOCAL_SRC_FILES :=  \
sodium_wrap.c

LOCAL_CFLAGS   += -Wall -g -pedantic -std=c99

ifeq ($(TARGET_ARCH_ABI), armeabi)
	LOCAL_C_INCLUDES += /home/gerard/pau/libsodium/libsodium-android-arm/include /home/gerard/pau/libsodium/libsodium-android-arm/include/sodium
endif

ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
	LOCAL_C_INCLUDES += /home/gerard/pau/libsodium/libsodium-android-armv7/include /home/gerard/pau/libsodium/libsodium-android-armv7/include/sodium
endif

LOCAL_STATIC_LIBRARIES += android_native_app_glue sodium

include $(BUILD_SHARED_LIBRARY)
