CC:=gcc
LD:=ld

TOPDIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOPBASE:=$(shell basename $(TOPDIR))
CBOR_CFLAGS:=$(shell pkg-config --cflags libcbor)
CBOR_LIBS:=$(shell pkg-config --libs libcbor)

# SUBDIRS:=app conf service state
# Exclude the src mid-level of the directory hierarchy, the include
# directory, and the object file directory.
SUBDIRS:=$(notdir $(wildcard $(TOPDIR)/src/*))
SRCDIR:=$(TOPDIR)/src
SRCDIRS:=$(addprefix $(SRCDIR)/,$(SUBDIRS))
OBJDIR:=$(TOPDIR)/obj
OBJDIRS:=$(addprefix $(OBJDIR)/,$(SUBDIRS))
INCDIR:=$(TOPDIR)/incl

LDFLAGS:=$(CBOR_LIBS)
CFLAGS:=-Wall -std=c23 $(CBOR_CFLAGS) -I$(INCDIR) -MD

vpath %.h $(INCDIR)
vpath %.c $(SRCDIRS)

SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(SUBDIRS))))
OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
DEP:=$(OBJ:%.o=%.d)

-include $(DEP)

# %.o: %.c
# $(OBJDIR)/app/%.o: %.c
	# @mkdir -p $(dir $@)
	# $(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
# $(OBJDIR)/conf/%.o: %.c
	# @mkdir -p $(dir $@)
	# $(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
# $(OBJDIR)/service/%.o: %.c
	# @mkdir -p $(dir $@)
	# $(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
# $(OBJDIR)/state/%.o: %.c
	# @mkdir -p $(dir $@)
	# $(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(addsuffix /%.o,$(OBJDIRS)): %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@

all:
	@echo SRC=$(SRC)
	@echo DEP=$(DEP)
	@echo OBJ=$(OBJ)
	@echo SRCDIRS=$(SRCDIRS)
	@echo OBJDIRS=$(OBJDIRS)
	@echo HVPATH=$(INCDIR)
	@echo CVPATH=$(subst  ,:,$(SRCDIRS))
	@echo OVPATH=$(subst  ,:,$(OBJDIRS))

c_trace_fwd: $(OBJ)
	@echo $+
	$(CC) $(LDFLAGS) $(OBJ) $(LIBS) -o $@
