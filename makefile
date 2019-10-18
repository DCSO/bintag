PROC=bintag

include ../plugin.mak

# use c++17
CXXSTD=-std=c++17

# MAKEDEP dependency list ------------------
$(F)bintag$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp bintag.cpp
