TARGET = bin/proxy_server.exe
BUILD_DIR = build
SRC_DIR = src
INCLUDE_DIR = include
LIB_DIR = lib

CXX = g++
CXXFLAGS = -Wall -std=c++17 -g -I$(INCLUDE_DIR)
LDFLAGS = -L$(LIB_DIR) -lssl -lcrypto -lws2_32 -lgdi32 -lgdiplus -mconsole

# Compile applink.c only once
APP_LINK_OBJ = $(BUILD_DIR)/applink.o

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))
OBJS += $(APP_LINK_OBJ)

$(TARGET): $(OBJS)
	mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile applink.c separately
$(APP_LINK_OBJ): include/openssl/applink.c
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(BUILD_DIR)/*.o $(TARGET)
