include config.mk

CFLAGS+=-I${WIRESHARKDIR} -DHAVE_STDARG_H -DHAVE_CONFIG_H -g
OBJECTS:=src/packet-isi.o \
	src/plugin.o \
	src/isi-sim.o \
	src/isi-simauth.o \
	src/isi-network.o \
	src/isi-gps.o \
	src/isi-ss.o \
	src/isi-gss.o \
	src/isi-sms.o \
	src/isi-mtc.o \
	src/isi-nameservice.o \
	src/isi-radiosettings.o \
	src/isi-phoneinfo.o

all: isi.so

%.o: %.c
	@echo "[CC] $<"
	@$(CC) -o $@ $(CFLAGS) `pkg-config --cflags glib-2.0` -c -fPIC $<

isi.so: $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) -o $@ -shared -Wl,-soname,$@ $^

clean:
	@rm -f isi.so src/*.o

install: isi.so
	install isi.so $(DESTDIR)${PREFIX}/${PLUGINDIR}

.PHONEY: all clean install
