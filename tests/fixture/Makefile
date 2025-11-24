CFLAGS += "-fdebug-prefix-map=${PWD}=/src"

FILES :=		\
	 subdir/bar.cpp \
	 subdir/foo.c	\
	 toplev.c	\

SHARED_FILES :=		\
	shared.c	\

OBJFILES := $(patsubst %,%.o,${FILES})
SHARED_OBJFILES := shared.c.so

%.c.o: %.c
	${CC} ${CFLAGS} -g -c -o $@ $^

%.c.so: %.c
	${CC} ${CFLAGS} -shared -o $@ $^
	strip $@

%.cpp.o: %.cpp
	${CXX} ${CFLAGS} -g -c -o $@ $^

default: ${OBJFILES} ${SHARED_OBJFILES}

clean:
	rm -f ${OBJFILES} ${SHARED_OBJFILES} compile_commands.json

compile_commands.json: ${FILES}
	bear -- ${MAKE} clean default

.PHONY: default clean
