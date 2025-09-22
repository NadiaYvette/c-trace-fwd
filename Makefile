# So that things are done in English:
LANG:=en_GB.UTF-8
GDM_LANG:=en_GB.UTF-8
LANGUAGE:=en_GB:en
# This should be compatible with either gcc or clang.
# CC:=clang
CC:=gcc
DBG:=$(shell which gdb)
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
APP_SUBDIRS:=app conf service state
LIB_SUBDIRS:=proto util
DOCDIR:=$(TOPDIR)/doc
IMGDIR:=$(TOPDIR)/img
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
INCFLAGS:=-I$(INCDIR) $(shell pkgconf --cflags glib-2.0)
CTF_LIBS:=c_trace_fwd

# The placement of the library is assumed in-place for the moment.
# Installation directories should follow.
PKGCONF_LIST:=libcbor glib-2.0
LDFLAGS:=-L$(OBJLIBDIR) \
		$(foreach PKG,$(PKGCONF_LIST), \
			$(shell pkgconf --libs --keep-system-libs $(PKG)))
LIBS:=$(CBOR_LIBS)

# -Wno-unused-function may sometimes be helpful.
# Theoretically, these could vary based on clang vs. gcc or other issues.
ifeq ($(CC),gcc)
DBGFLAGS:=-g -gdwarf-3 -fvar-tracking-assignments
else
DBGFLAGS:=-g -gdwarf-3
endif
OPTFLAGS:=-Og
STDFLAGS:=-std=gnu23
WARNFLAGS:=-Wall
CGENFLAGS:=$(DBGFLAGS) $(OPTFLAGS) $(STDFLAGS) $(WARNFLAGS)
CFLAGS:=$(CGENFLAGS) $(CBOR_CFLAGS) $(INCFLAGS) -MD
ENVFLAGS:=-S GDM_LANG=en_GB.UTF-8 LANG=en_GB.UTF-8 LANGUAGE=en_GB:en 

vpath %.ltx $(DOCDIR)
vpath %.pdf $(DOCDIR)
vpath %.svg $(IMGDIR)
vpath %.tikz $(DOCDIR)
vpath %.h $(INCDIR)
vpath %.c $(APP_SRCDIRS) $(LIB_SRCDIRS) $(TSTDIR)

APP_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(APP_SUBDIRS))))
BIB_SRC:=$(wildcard $(addsuffix /*.bib,$(DOCDIR)))
DOC_SRC:=$(wildcard $(addsuffix /*.ltx,$(DOCDIR)))
DOC_MAIN_SRC:=$(DOCDIR)/cardiff.ltx
IMG_SRC:=$(wildcard $(addsuffix /*.svg,$(IMGDIR)))
LIB_SRC:=$(wildcard $(addsuffix /*.c,$(addprefix $(SRCDIR)/,$(LIB_SUBDIRS))))
TST_SRC:=$(wildcard $(addsuffix /*.c,$(TSTDIR)))
HDR_SRC:=$(wildcard $(INCDIR)/*.h)
APP_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(APP_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
IMG_TIKZ:=$(patsubst %.svg,%.tikz,$(foreach FILE,$(IMG_SRC),$(DOCDIR)/$(shell realpath --relative-to=$(IMGDIR) $(FILE))))
LIB_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(LIB_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(SRCDIR) $(FILE))))
TST_OBJ:=$(patsubst %.c,%.o,$(foreach FILE,$(TST_SRC),$(OBJDIR)/$(shell realpath --relative-to=$(TOPDIR) $(FILE))))
OBJ:=$(APP_OBJ) $(LIB_OBJ) $(TST_OBJ)
DEP:=$(OBJ:%.o=%.d)
DOC:=$(DOCDIR)/cardiff.pdf

CTF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,c_trace_fwd)
CTF_LIB_DSO:=$(addprefix $(OBJLIBDIR)/lib,$(addsuffix .so,$(CTF_LIBS)))
CBOR_BIN_EXE:=$(addprefix $(OBJBINDIR)/,cbor_dissect)
DSC_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_cbor_dsc)
EMP_BIN_EXE:=$(addprefix $(OBJBINDIR)/,empty_loop)
RNC_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_reencode)
SDU_BIN_EXE:=$(addprefix $(OBJBINDIR)/,sdu_dissect)
TOF_BIN_EXE:=$(addprefix $(OBJBINDIR)/,tof_stdin)
TRY_BIN_EXE:=$(addprefix $(OBJBINDIR)/,cbor_try)

$(CTF_BIN_EXE): $(APP_OBJ) $(CTF_LIB_DSO)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $(APP_OBJ) $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(CBOR_BIN_EXE): $(OBJDIR)/test/cbor_dissect.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(CTF_LIB_DSO): $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(DBGFLAGS) -shared $(LIB_OBJ) $(LIBS) -o $@

$(DSC_BIN_EXE): $(OBJDIR)/test/sdu_cbor_dsc.o $(CTF_LIB_DSO)
	@mkdir -p $(dir @)
	$(CC) $(LDFLAGS) $(DBGFLAGS) $+ $(LIBS) $(addprefix -l,$(CTF_LIBS)) -o $@

$(EMP_BIN_EXE): $(OBJDIR)/test/empty_loop.o $(CTF_LIB_DSO)
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

.PHONY: all allclean check clean ckclean depclean doc dbg-run trace-compare

all: $(CBOR_BIN_EXE) $(CTF_BIN_EXE) $(CTF_LIB_DSO) $(DSC_BIN_EXE) \
	$(EMP_BIN_EXE) $(RNC_BIN_EXE) $(SDU_BIN_EXE) $(TOF_BIN_EXE) \
	$(TRY_BIN_EXE)

check:
	# The per-C source file plist files don't mirror the
	# filesystem hierarchy as expected; however, they don't appear
	# to have meaningful content in observed cases and are largely
	# undocumented. So it seems to be no great loss.
	clang-check --analyze -p ./ \
		$(APP_SRC) $(HDR_SRC) $(LIB_SRC) $(TST_SRC) \
		--analyzer-output-path=$(OBJDIR)/analysis \
		-- \
		-std=gnu23 $(INCFLAGS) -isystem /usr/include \
		-isystem /usr/lib/clang/19/include

allclean: ckclean clean depclean

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

doc: $(DOC) $(BIB_SRC) $(DOC_SRC) $(IMG_TIKZ)
	env $(ENVFLAGS) $(LATEX) $(LATEXFLAGS) $(DOC_MAIN_SRC) && \
	env $(ENVFLAGS) $(BIBER) $(BIBERFLAGS) $(patsubst %.ltx,%.bcf,\
		$(foreach FILE,$(DOC_SRC),\
		$(DOCDIR)/$(shell realpath --relative-to=$(DOCDIR) $(FILE)))) \
		&& \
	env $(ENVFLAGS) $(LATEX) $(LATEXFLAGS) $(DOC_MAIN_SRC) && \
	env $(ENVFLAGS) $(LATEX) $(LATEXFLAGS) $(DOC_MAIN_SRC)

TRACER_SOCKET:=$(HOME)/src/tracer-repl-mod/mainnetsingle/socket/tracer.socket
LISTEN_ADDRESS:=127.0.0.1:9191
dbg-run: $(CTF_BIN_EXE) $(CTF_LIB_DSO)
	LD_PRELOAD=$(CTF_LIB_DSO) $(DBG) $(CTF_BIN_EXE) \
		   --eval-command="r -f $(TRACER_SOCKET) -u $(LISTEN_ADDRESS)"
