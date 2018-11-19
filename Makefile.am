AUTOMAKE_OPTIONS = gnu
sysconf_DATA = p0f.fp
EXTRA_DIST = $(sysconf_DATA)
sbin_PROGRAMS=p0f

p0f_SOURCES = alloc-inl.h  api.h  config.h  debug.h  fp_http.h  fp_mtu.h  fp_tcp.h  hash.h  languages.h  p0f.h  process.h  readfp.h  tcp.h  types.h
p0f_SOURCES += api.c  fp_http.c  fp_mtu.c  fp_tcp.c  p0f.c  process.c  readfp.c

p0f_CPPFLAGS=-DCONFIGDIR="$(sysconfdir)"
p0f_CFLAGS = -Wall -Wno-format
p0f_CFLAGS +=-fstack-protector-all -fPIE -D_FORTIFY_SOURCE=2
 
 
p0f_LDFLAGS = -lpcap  -Wl,-z,relro 
p0f_LDFLAGS += -fPIE -flto -Wl,--build-id=sha1 -rdynamic




