# This should be compatible with either gcc or clang.
CC:=clang
# CC:=gcc
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
TSTDIR:=$(TOPDIR)/test
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
ifeq ($(CC),gcc)
DBGFLAGS:=-g -gdwarf-3 -fvar-tracking-assignments
else
DBGFLAGS:=-g -gdwarf-3
endif
OPTFLAGS:=-O0
STDFLAGS:=-std=gnu23
WARNFLAGS:=-Wall
CGENFLAGS:=$(DBGFLAGS) $(OPTFLAGS) $(STDFLAGS) $(WARNFLAGS)
CFLAGS:=$(CGENFLAGS) $(CBOR_CFLAGS) $(INCFLAGS) -MD

vpath %.h $(INCDIR)
vpath %.c $(APP_SRCDIRS) $(LIB_SRCDIRS) $(TSTDIR)

APP_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(APP_SUBDIRS))))
LIB_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(LIB_SUBDIRS))))
HDR:=$(wildcard $(HDR)/*.h)
APP_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(APP_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
LIB_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(LIB_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
OBJ:=$(APP_OBJ) $(LIB_OBJ)
DEP:=$(OBJ:%.o=%.d)

CBOR_BIN_EXE:=$(addprefix $(OBJBINDIR)/,cbor_dissect)
CTF_LIB_DSO:=$(addprefix $(OBJLIBDIR)/lib,$(addsuffix .so,$(CTF_LIBS)))
CTF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,c_trace_fwd)
DSC_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_cbor_dsc)
SDU_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_dissect)
RNC_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_reencode)
TOF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,tof_stdin)
TRY_BIN_EXE:=$(addprefix $(OBJBINDIR)/,cbor_try)

$(CBOR_BIN_EXE): $(OBJDIR)/test/cbor_dissect.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(CTF_BIN_EXE): $(APP_OBJ) $(CTF_LIB_DSO)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $(APP_OBJ) $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(CTF_LIB_DSO): $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(DBGFLAGS) -shared $(LIB_OBJ) $(LIBS) -o $@

$(DSC_BIN_EXE): $(OBJDIR)/test/sdu_cbor_dsc.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(RNC_BIN_EXE): $(OBJDIR)/test/sdu_reencode.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(SDU_BIN_EXE): $(OBJDIR)/test/sdu_dissect.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(TOF_BIN_EXE): $(OBJDIR)/test/tof_stdin.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(TRY_BIN_EXE): $(OBJDIR)/test/cbor_try.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

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

.PHONY: check clean ckclean depclean trace-compare
check:
	# The per-C source file plist files don't mirror the
	# filesystem hierarchy as expected; however, they don't appear
	# to have meaningful content in observed cases and are largely
	# undocumented. So it seems to be no great loss.
	clang-check --analyze -p ./ \
		$(shell find $(INCDIR) $(SRCDIR) -name '*.[ch]') \
		--analyzer-output-path=$(OBJDIR)/analysis \
		-- \
		-std=gnu23 -I./incl -isystem /usr/include \
		-isystem /usr/lib/clang/19/include
ckclean:
	-rm -f $(wildcard *.plist) $(wildcard $(OBJDIR)/*.plist) \
		$(OBJDIR)/analysis
clean:
	-rm -f $(OBJ) $(CTF_LIB_DSO) $(CBOR_BIN_EXE) \
		$(CTF_BIN_EXE) $(DSC_BIN_EXE) $(SDU_BIN_EXE) \
		$(RNC_BIN_EXE) $(TOF_BIN_EXE) $(TRY_BIN_EXE)

depclean:
	-rm -f $(DEP)

trace-compare: $(shell find $(TSTDIR) -name '*.hs')
	find $(TOPDIR) -name '*.[mt]ix' -exec rm -f \{\} \;
	cd $(TSTDIR); cabal run trace-compare:exe:trace-compare \
		-- ../logs/*.007.A ../logs/*.007.D

trace-compare-repl: $(shell find $(TSTDIR) -name '*.hs')
	find $(TOPDIR) -name '*.[mt]ix' -exec rm -f \{\} \;
	cd $(TSTDIR); cabal repl trace-compare:exe:trace-compare
