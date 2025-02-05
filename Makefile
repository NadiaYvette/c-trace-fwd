# This should be compatible with either gcc or clang.
# CC:=clang
CC:=gcc
LD:=$(CC)

TOPDIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOPBASE:=$(shell basename $(TOPDIR))
CBOR_CFLAGS:=$(shell pkg-config --cflags libcbor)
CBOR_LIBS:=$(shell pkg-config --libs libcbor)

# Divide the directories between the app and the lib.
# Without that distinction, the following would happen:
# SUBDIRS:=$(notdir $(wildcard $(TOPDIR)/src/*))
# SUBDIRS:=app conf proto service state
# More libraries may need more variables in this scheme.
APP_SUBDIRS:=app conf service state util
LIB_SUBDIRS:=proto util
SRCDIR:=$(TOPDIR)/src
APP_SRCDIRS:=$(addprefix $(SRCDIR)/,$(APP_SUBDIRS))
LIB_SRCDIRS:=$(addprefix $(SRCDIR)/,$(LIB_SUBDIRS))
OBJDIR:=$(TOPDIR)/obj
APP_OBJDIRS:=$(addprefix $(OBJDIR)/,$(APP_SUBDIRS))
LIB_OBJDIRS:=$(addprefix $(OBJDIR)/,$(LIB_SUBDIRS))
OBJBINDIR:=$(OBJDIR)/bin
OBJLIBDIR:=$(OBJDIR)/lib
INCDIR:=$(TOPDIR)/incl
INCFLAGS:=-I$(INCDIR)
CTF_LIBS:=c_trace_fwd

# The placement of the library is assumed in-place for the moment.
# Installation directories should follow.
LDFLAGS:=-L$(OBJLIBDIR)
LIBS:=$(CBOR_LIBS)

# -Wno-unused-function may sometimes be helpful.
# Theoretically, these could vary based on clang vs. gcc or other issues.
DBGFLAGS:=-g
OPTFLAGS:=-O0
STDFLAGS:=-std=gnu23
WARNFLAGS:=-Wall
CGENFLAGS:=$(DBGFLAGS) $(OPTFLAGS) $(STDFLAGS) $(WARNFLAGS)
CFLAGS:=$(CGENFLAGS) $(CBOR_CFLAGS) $(INCFLAGS) -MD

vpath %.h $(INCDIR)
vpath %.c $(APP_SRCDIRS) $(LIB_SRCDIRS) $(SRCDIR)/test

APP_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(APP_SUBDIRS))))
LIB_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(LIB_SUBDIRS))))
HDR:=$(wildcard $(HDR)/*.h)
APP_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(APP_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
LIB_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(LIB_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
OBJ:=$(APP_OBJ) $(LIB_OBJ)
DEP:=$(OBJ:%.o=%.d)

CTF_LIB_DSO:=$(addprefix $(OBJLIBDIR)/lib,$(addsuffix .so,$(CTF_LIBS)))
CTF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,c_trace_fwd)
TOF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,tof_stdin)

$(CTF_BIN_EXE): $(APP_OBJ) $(CTF_LIB_DSO)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(APP_OBJ) $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(CTF_LIB_DSO): $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -shared $(LIB_OBJ) $(LIBS) -o $@

$(TOF_BIN_EXE): $(OBJDIR)/test/tof_stdin.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

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
	$(CC) $(CFLAGS) -fPIC -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/service/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/state/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/test/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@
$(OBJDIR)/util/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fPIC -c $< -MD -MF $(@:%.o=%.d) -MT $@ -o $@

.PHONY: check clean depclean
check:
	clang-check --analyze -p ./ \
		$(shell find $(INCDIR) $(SRCDIR) -name '*.[ch]') -- \
		-std=gnu23 -I./incl -isystem /usr/include \
		-isystem /usr/lib/clang/19/include
clean:
	-rm -f $(OBJ) $(CTF_LIB_DSO) $(CTF_BIN_EXE) $(TOF_BIN_EXE)

depclean:
	-rm -f $(DEP)
