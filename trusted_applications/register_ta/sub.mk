# TA sources
srcs-y += register_ta.c

# Header is in the parent folder: linuxptp/trusted_applications/register_ta.h
global-incdirs-y += ..
# (optional) warnings
cflags-y += -Wall -Wextra
