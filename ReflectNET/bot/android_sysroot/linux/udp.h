#pragma once
#include "../../headers/android_compat.h"
#ifndef ANDROID
#include_next <linux/udp.h>
#endif
