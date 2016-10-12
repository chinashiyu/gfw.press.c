#
#
#	Description:	makefile 编译规则
#	Revisions:		Year-Month-Day  SVN-Author  Modification
#

CROSS =

CPP	= @echo " g++ $@"; $(CROSS)g++
CC	= @echo " gcc $@"; $(CROSS)gcc
LD	= @echo " ld  $@"; $(CROSS)ld
AR  = @echo " ar  $@"; $(CROSS)ar
RM	= @echo " RM	$@"; rm -f
STRIP	= @echo " strip  $@"; $(CROSS)strip


TARGET = gfw.press

DIRSRC = ./src

SRCS = $(wildcard ${DIRSRC}/*.c)  
LIB_OBJS = $(SRCS:%.c=%.o)

CCFLAGS += -ansi -O3  -lssl -lcrypto -lpthread -Wall -g

$(TARGET) : $(LIB_OBJS)
	$(RM) $@;
	$(CC) $^ -o $@ $(CCFLAGS)

#编译规则
%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(TARGET) $(LIB_OBJS)
	
.PHONY: clean
