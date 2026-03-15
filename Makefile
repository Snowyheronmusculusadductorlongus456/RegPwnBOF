BOFNAME := regpwn
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o -Os -Wall -Wextra -Wno-unused-parameter -c entry.c -DBOF

test:
	$(CC_x64) entry.c -o $(BOFNAME).x64.exe -ladvapi32 -luser32 -lntdll -lshell32

check:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction --platform=win64 entry.c

clean:
	rm -f $(BOFNAME).x64.o $(BOFNAME).x64.exe
