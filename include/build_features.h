#pragma once

#if defined(FILESEND_PROFILE_MINIMAL)
  #define FILESEND_ENABLE_HTTP        0
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          0
  #define FILESEND_ENABLE_BATCH       0
  #define FILESEND_ENABLE_DB          0
#elif defined(FILESEND_PROFILE_FULL)
  #define FILESEND_ENABLE_HTTP        1
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          1
  #define FILESEND_ENABLE_BATCH       1
  #define FILESEND_ENABLE_DB          1
#elif defined(FILESEND_PROFILE_TEST)
  #define FILESEND_ENABLE_HTTP        1
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          0
  #define FILESEND_ENABLE_BATCH       1
  #define FILESEND_ENABLE_DB          0
#else
  #error "Define FILESEND_PROFILE_MINIMAL, FILESEND_PROFILE_TEST or FILESEND_PROFILE_FULL"
#endif
