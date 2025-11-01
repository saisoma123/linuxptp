# TA sources
srcs-y += trusted_bmca.c

# Headers shared with host live one level up (bmca_ta.h)
global-incdirs-y += . ..
global-incdirs-y += $(CURDIR)/..
