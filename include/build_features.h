#pragma once

// NOTE: if your setup requires custom configuration, modify the options under FILESEND_PROFILE_CUSTOM

// Includes only core features (sending over WS + enc/dec)
#if defined(FILESEND_PROFILE_MINIMAL_WS)
  #define FILESEND_ENABLE_HTTP        0
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          0
  #define FILESEND_ENABLE_BATCH       0
  #define FILESEND_ENABLE_DB          0

// Includes only core features (sending over HTTP + enc/dec)
#elif defined(FILESEND_PROFILE_MINIMAL_HTTP)
  #define FILESEND_ENABLE_HTTP        1
  #define FILESEND_ENABLE_WS          0
  #define FILESEND_ENABLE_MT          0
  #define FILESEND_ENABLE_BATCH       0
  #define FILESEND_ENABLE_DB          0

// Includes all the features (sending over WS/HTTP + enc/dec, multithreading, batching, DB, etc)
#elif defined(FILESEND_PROFILE_FULL)
  #define FILESEND_ENABLE_HTTP        1
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          1
  #define FILESEND_ENABLE_BATCH       1
  #define FILESEND_ENABLE_DB          1

#elif defined(FILESEND_PROFILE_CUSTOM)
  #define FILESEND_ENABLE_HTTP        0
  #define FILESEND_ENABLE_WS          1
  #define FILESEND_ENABLE_MT          0
  #define FILESEND_ENABLE_BATCH       1
  #define FILESEND_ENABLE_DB          1
#else
  #error "Define FILESEND_PROFILE_MINIMAL_WS, FILESEND_PROFILE_MINIMAL_HTTP, FILESEND_PROFILE_CUSTOM or FILESEND_PROFILE_FULL"
#endif
