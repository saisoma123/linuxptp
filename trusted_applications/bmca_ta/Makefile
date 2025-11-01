ifndef TA_DEV_KIT_DIR
$(error TA_DEV_KIT_DIR is not set)
endif

# TA sources
srcs-y += bmca_ta.c

# Include dirs (point to shared header in the same repo)
global-incdirs-y += . ..
global-incdirs-y += $(CURDIR)/..    # so bmca_ta.h in parent trusted_applications/ is visible

# Build with OP-TEE TA Dev Kit
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
