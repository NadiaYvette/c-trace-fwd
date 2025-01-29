# This should be compatible with either gcc or clang.
# CC:=clang
CC:=gcc
LD:=$(CC)

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
OBJBINDIR:=$(OBJDIR)/bin
OBJLIBDIR:=$(OBJDIR)/lib
INCDIR:=$(TOPDIR)/incl
INCFLAGS:=-I$(INCDIR)

LDFLAGS:=$(CBOR_LIBS)

# -Wno-unused-function may sometimes be helpful.
# Theoretically, these could vary based on clang vs. gcc or other issues.
DBGFLAGS:=-g
OPTFLAGS:=-O
STDFLAGS:=-std=gnu23
WARNFLAGS:=-Wall
CGENFLAGS:=$(DBGFLAGS) $(OPTFLAGS) $(STDFLAGS) $(WARNFLAGS)
CFLAGS:=$(CGENFLAGS) $(CBOR_CFLAGS) $(INCFLAGS) -MD

vpath %.h $(INCDIR)
vpath %.c $(SRCDIRS)

SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(SUBDIRS))))
HDR:=$(wildcard $(HDR)/*.h)
OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
DEP:=$(OBJ:%.o=%.d)

$(OBJBINDIR)/c_trace_fwd: $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBS) -o $@

-include $(DEP)

# %.o: %.c
$(OBJDIR)/app/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/conf/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/drv/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/proto/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/service/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/state/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/util/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@

.PHONY: check clean
check:
	clang-check --analyze -p ./ \
		$(shell find $(INCDIR) $(SRCDIR) -name '*.[ch]') -- \
		-std=gnu23 -I./incl -isystem /usr/include \
		-isystem /usr/lib/clang/19/include
clean:
	-rm -f $(OBJ)
