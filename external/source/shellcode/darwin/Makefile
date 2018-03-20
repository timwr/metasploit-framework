CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -Os -O0
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BIN_IOS=`xcrun --sdk iphoneos -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) $(CFLAGS)
GCC_BASE_IOS=$(GCC_BIN_IOS) $(CFLAGS)
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64
SDK_IOS=`xcrun --sdk iphoneos --show-sdk-path`
GCC_IOS=$(GCC_BASE_IOS) -arch arm64 -isysroot $(SDK_IOS)

all: clean main_osx main_ios

main_osx: main.c
	$(GCC_OSX) -o $@ $^

main_ios: main.c
	$(GCC_IOS) -o $@ $^

shellcode: main_osx
	otool -tv main_osx

install: main_ios
	cp main_ios ../../../../data/meterpreter/aarch64_iphone_darwin_stage

clean:
	rm -f *.o main_osx main_ios

