CXX      := g++
CXXFLAGS := -std=c++23 -fmodules-ts -O3 -Wall -Wextra -fPIC
LDLIBS   := -ltss2-esys

TARGET   := libtpm23.a

MODULE_INTERFACES := status.cppm nv.cppm policy.cppm crypto.cppm core.cppm tpm23.cppm
OBJS              := status.o nv.o policy.o crypto.o core.o tpm23.o

.PHONY: all clean test

all: $(TARGET)

status.o: src/status.cppm
	@echo "[GCC] Translating module: tpm23.status..."
	$(CXX) $(CXXFLAGS) -c src/status.cppm -o status.o

nv.o: src/nv.cppm status.o
	@echo "[GCC] Translating module: tpm23.nv..."
	$(CXX) $(CXXFLAGS) -c src/nv.cppm -o nv.o

policy.o: src/policy.cppm status.o
	@echo "[GCC] Translating module: tpm23.policy..."
	$(CXX) $(CXXFLAGS) -c src/policy.cppm -o policy.o

crypto.o: src/crypto.cppm status.o
	@echo "[GCC] Translating module: tpm23.crypto..."
	$(CXX) $(CXXFLAGS) -c src/crypto.cppm -o crypto.o

core.o: src/core.cppm status.o nv.o policy.o crypto.o
	@echo "[GCC] Translating module: tpm23.core..."
	$(CXX) $(CXXFLAGS) -c src/core.cppm -o core.o

tpm23.o: src/tpm23.cppm core.o nv.o policy.o crypto.o status.o
	@echo "[GCC] Translating primary module export bundle..."
	$(CXX) $(CXXFLAGS) -c src/tpm23.cppm -o tpm23.o

$(TARGET): $(OBJS)
	@echo "[ARCHIVE] Packing multi-module static library..."
	ar rcs $(TARGET) $(OBJS)

test: $(TARGET) main.cpp
	@echo "[BUILD] Compiling C++23 test validation harness..."
	$(CXX) $(CXXFLAGS) main.cpp -L. -ltpm23 $(LDLIBS) -o run_tests
	@echo "[RUN] Executing automated component test suite..."
	./run_tests

clean:
	@echo "[CLEAN] Purging target files, binaries, and module caches..."
	rm -rf $(OBJS) $(TARGET) run_tests gcm.cache/
