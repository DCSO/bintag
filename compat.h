#pragma once

/* For backwards compatibility with IDA SDKs < 7.3 */
#if IDA_SDK_VERSION < 730
#define inf_get_min_ea()        inf.min_ea
#define inf_is_64bit()          inf.is_64bit()
#define inf_is_32bit()          inf.is_32bit()
#define WOPN_DP_TAB             WOPN_TAB
#endif
