# Makefile - KCP-over-AF_PACKET
# Production-quality build system with automatic dependency tracking.

CC      := gcc

# -------------------- 目录 --------------------
SRCDIR  := src
OBJDIR  := obj
TARGET  := gapproxy

# -------------------- 源文件 --------------------
SRCS := $(SRCDIR)/main.c \
        $(SRCDIR)/af_packet.c \
        $(SRCDIR)/myproto.c \
        $(SRCDIR)/crypto.c \
        $(SRCDIR)/kcp_wrap.c \
        $(SRCDIR)/channel.c \
        $(SRCDIR)/proxy.c \
        $(SRCDIR)/acl.c \
        $(SRCDIR)/mgmt.c \
        $(SRCDIR)/api.c \
        $(SRCDIR)/plugin.c \
        $(SRCDIR)/ikcp.c

# -------------------- 目标文件与依赖文件 --------------------
OBJS := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
OBJS += $(OBJDIR)/mongoose.o
DEPS := $(OBJS:.o=.d)

# -------------------- 编译选项 --------------------
# -I/tmp/json-stub 为开发期间临时存根路径，供 json-c 头文件缺失时编译通过。
# 正式部署应通过 pkg-config 或标准路径提供 json-c 头文件。
# M18-STUB: 若系统安装了 json-c，可替换为:
#   INCLUDES := -I$(SRCDIR) -Ivendor/mongoose $(shell pkg-config --cflags json-c)
INCLUDES := -I$(SRCDIR) -Ivendor/mongoose -I/tmp/json-stub 

# M19: -Werror 将警告视为错误，确保生产构建零警告。若编译器版本差异
# 导致误报，可使用 `make dev` 目标（无 -Werror）进行开发调试。
CFLAGS_BASE  := -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE $(INCLUDES)

# Release (default)
CFLAGS       := $(CFLAGS_BASE) -O2

# Dev build: 宽松警告（无 -Werror），适合开发期间快速迭代
dev: CFLAGS := -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -g -O0 $(INCLUDES)
dev: all

# LDFLAGS
LDFLAGS      := -ljson-c -lrt -lnettle -lpthread

# -------------------- 安装路径 --------------------
PREFIX       ?= /usr/local
INSTALL_BIN  := $(PREFIX)/bin

# -------------------- 伪目标 --------------------
.PHONY: all clean debug dev install test test-prod test-clean

all: $(TARGET)

# -------------------- 链接 --------------------
$(TARGET): $(OBJS)
	@echo "  LD      $@"
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# -------------------- 编译（含自动依赖生成） --------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# -------------------- mongoose (third-party) --------------------
$(OBJDIR)/mongoose.o: vendor/mongoose/mongoose.c
	@mkdir -p $(@D)
	@echo "  CC_MON  $<"
	$(CC) $(CFLAGS) -MMD -MP -Wno-unused-parameter -Wno-sign-compare -c $< -o $@

# -------------------- 包含自动生成的依赖 --------------------
-include $(DEPS)

# -------------------- Debug 构建 --------------------
debug: CFLAGS := $(CFLAGS_BASE) -g -O0 -DDEBUG
debug: all

# -------------------- 清理 --------------------
clean: test-clean
	@echo "  CLEAN"
	rm -rf $(OBJDIR) $(TARGET)

# -------------------- 安装 --------------------
install: $(TARGET)
	@echo "  INSTALL $(TARGET) -> $(INSTALL_BIN)/"
	install -d $(INSTALL_BIN)
	install -m 755 $(TARGET) $(INSTALL_BIN)/

# -------------------- 帮助 --------------------
help:
	@echo "KCP-over-AF_PACKET Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       Build release binary (default)"
	@echo "  debug     Build debug binary (-g -O0 -DDEBUG)"
	@echo "  clean     Remove build artifacts"
	@echo "  install   Install to $(INSTALL_BIN)/"
	@echo "  test      Build and run unit tests"
	@echo "  help      Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CC        C compiler          (default: gcc)"
	@echo "  PREFIX    Install prefix      (default: /usr/local)"
	@echo ""
	@echo "Example:"
	@echo "  make debug && ./gapproxy config.json"

# -------------------- 测试 --------------------
TEST_CFLAGS   := -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g

# 单元测试
TEST_MYPROTO_SRC := tests/test_myproto.c src/myproto.c src/crypto.c
TEST_MYPROTO_LIBS := -lnettle
TEST_MYPROTO_BIN := tests/test_myproto

# 集成测试
TEST_INTEG_SRC   := tests/test_integration.c src/main.c src/af_packet.c src/myproto.c src/crypto.c src/kcp_wrap.c src/channel.c src/plugin.c src/proxy.c src/acl.c src/ikcp.c
TEST_INTEG_BIN   := tests/test_integration
TEST_INTEG_FLAGS := $(TEST_CFLAGS) -DTEST_BUILD -Wno-unused-function
TEST_INTEG_LIBS  := -ljson-c -lrt -lnettle

# 对比测试（与原始项目 KCP-over-AF_PACKET 的交叉验证）
TEST_COMPARE_SRC  := tests/test_comparison.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c src/af_packet.c src/proxy.c
TEST_COMPARE_BIN  := tests/test_comparison
TEST_COMPARE_LIBS := -lrt -lnettle

# 扩展集成测试（20个新方法）
TEST_INTEG2_SRC  := tests/test_integration_v2.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG2_BIN  := tests/test_integration_v2
TEST_INTEG2_LIBS := -lrt -lnettle

# 多会话功能集成测试（20个新方法）
TEST_INTEG3_SRC  := tests/test_integration_v3.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG3_BIN  := tests/test_integration_v3
TEST_INTEG3_LIBS := -lrt -lnettle

# 通道热重载 & uint32 channel_id 集成测试
TEST_INTEG4_SRC  := tests/test_integration_v4.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG4_BIN  := tests/test_integration_v4
TEST_INTEG4_LIBS := -lrt -lnettle

# 全量集成测试 v5 (100项)
TEST_INTEG5_SRC  := tests/test_integration_v5.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c
TEST_INTEG5_BIN  := tests/test_integration_v5
TEST_INTEG5_LIBS := -lrt -lnettle

# 全量集成测试 v6 (24项 — crypto/channel_id/EPOLL/time/state)
TEST_INTEG6_SRC  := tests/test_integration_v6.c src/myproto.c src/crypto.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c src/acl.c
TEST_INTEG6_BIN  := tests/test_integration_v6
TEST_INTEG6_LIBS := -lrt -lnettle

.PHONY: test test-unit test-integ test-integ2 test-integ3 test-integ4 test-integ5 test-integ6 test-compare test-clean

test: test-unit test-integ test-integ2 test-integ3 test-integ4 test-integ5 test-integ6 test-compare

test-unit: $(TEST_MYPROTO_BIN)
	@echo "  RUN     $(TEST_MYPROTO_BIN)"
	@./$(TEST_MYPROTO_BIN)

test-integ: $(TEST_INTEG_BIN)
	@echo "  RUN     $(TEST_INTEG_BIN)"
	@./$(TEST_INTEG_BIN)

test-integ2: $(TEST_INTEG2_BIN)
	@echo "  RUN     $(TEST_INTEG2_BIN)"
	@./$(TEST_INTEG2_BIN)

test-integ3: $(TEST_INTEG3_BIN)
	@echo "  RUN     $(TEST_INTEG3_BIN)"
	@./$(TEST_INTEG3_BIN)

test-integ4: $(TEST_INTEG4_BIN)
	@echo "  RUN     $(TEST_INTEG4_BIN)"
	@./$(TEST_INTEG4_BIN)

test-integ5: $(TEST_INTEG5_BIN)
	@echo "  RUN     $(TEST_INTEG5_BIN)"
	@./$(TEST_INTEG5_BIN)

test-integ6: $(TEST_INTEG6_BIN)
	@echo "  RUN     $(TEST_INTEG6_BIN)"
	@./$(TEST_INTEG6_BIN)

$(TEST_MYPROTO_BIN): $(TEST_MYPROTO_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_MYPROTO_SRC) $(TEST_MYPROTO_LIBS)

$(TEST_INTEG_BIN): $(TEST_INTEG_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_INTEG_FLAGS) -o $@ $(TEST_INTEG_SRC) $(TEST_INTEG_LIBS)

test-clean:
	@echo "  CLEAN   tests"
	rm -f $(TEST_MYPROTO_BIN) $(TEST_INTEG_BIN) \
	      $(TEST_COMPARE_BIN) \
	      $(TEST_INTEG2_BIN) $(TEST_INTEG3_BIN) \
	      $(TEST_INTEG4_BIN) $(TEST_INTEG5_BIN) $(TEST_INTEG6_BIN) \
	      $(TEST_PROD_CRYPTO_BIN) $(TEST_PROD_CHANNEL_BIN) \
	      $(TEST_PROD_KCP_BIN) $(TEST_PROD_CONFIG_BIN) \
	      $(TEST_PROD_INTEG_BIN) $(TEST_PROD_MGMT_BIN) \
      $(TEST_PROD_API_BIN)

test-compare: $(TEST_COMPARE_BIN)
	@echo "  RUN     $(TEST_COMPARE_BIN)"
	@./$(TEST_COMPARE_BIN)

$(TEST_COMPARE_BIN): $(TEST_COMPARE_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_COMPARE_SRC) $(TEST_COMPARE_LIBS)

$(TEST_INTEG2_BIN): $(TEST_INTEG2_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG2_SRC) $(TEST_INTEG2_LIBS)

$(TEST_INTEG3_BIN): $(TEST_INTEG3_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG3_SRC) $(TEST_INTEG3_LIBS)

$(TEST_INTEG4_BIN): $(TEST_INTEG4_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG4_SRC) $(TEST_INTEG4_LIBS)

$(TEST_INTEG5_BIN): $(TEST_INTEG5_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	# -mcmodel=medium: v5 测试包含大量静态数据 (>2GB 寻址范围), 避免 relocation 截断
	$(CC) $(TEST_CFLAGS) -mcmodel=medium -o $@ $(TEST_INTEG5_SRC) $(TEST_INTEG5_LIBS)

$(TEST_INTEG6_BIN): $(TEST_INTEG6_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_INTEG6_SRC) $(TEST_INTEG6_LIBS)

# ──── Production Test Suite (500+ cases) ────
TEST_PROD_CRYPTO_SRC := tests/test_production_crypto.c src/crypto.c src/myproto.c
TEST_PROD_CHANNEL_SRC := tests/test_production_channel.c src/channel.c src/plugin.c src/proxy.c src/kcp_wrap.c src/ikcp.c src/myproto.c src/crypto.c 
TEST_PROD_KCP_SRC := tests/test_production_kcp.c src/kcp_wrap.c src/ikcp.c src/acl.c
TEST_PROD_CONFIG_SRC := tests/test_production_config.c
TEST_PROD_INTEG_SRC := tests/test_production_integ.c src/channel.c src/plugin.c src/kcp_wrap.c src/ikcp.c src/myproto.c src/crypto.c 
TEST_PROD_MGMT_SRC := tests/test_production_mgmt.c src/crypto.c
TEST_PROD_API_SRC := tests/test_production_api.c src/api.c src/mgmt.c src/channel.c src/plugin.c src/proxy.c src/kcp_wrap.c src/ikcp.c src/myproto.c src/crypto.c

TEST_PROD_CRYPTO_BIN := tests/test_production_crypto
TEST_PROD_CHANNEL_BIN := tests/test_production_channel
TEST_PROD_KCP_BIN := tests/test_production_kcp
TEST_PROD_CONFIG_BIN := tests/test_production_config
TEST_PROD_INTEG_BIN := tests/test_production_integ
TEST_PROD_MGMT_BIN := tests/test_production_mgmt
TEST_PROD_API_BIN := tests/test_production_api

TEST_PROD_FLAGS := -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g
TEST_PROD_LIBS := -lrt -lnettle -lpthread
TEST_PROD_API_FLAGS := -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -DTEST_BUILD -Isrc -Ivendor/mongoose -I/tmp/json-stub -O0 -g
TEST_PROD_API_LIBS := -ljson-c -lrt -lnettle -lpthread

tests/test_production_crypto: $(TEST_PROD_CRYPTO_SRC)
	$(CC) $(TEST_PROD_FLAGS) -o $@ $^ $(TEST_PROD_LIBS)

tests/test_production_channel: $(TEST_PROD_CHANNEL_SRC) 
	$(CC) $(TEST_PROD_FLAGS) -o $@ $^ $(TEST_PROD_LIBS)

tests/test_production_kcp: $(TEST_PROD_KCP_SRC)
	$(CC) $(TEST_PROD_FLAGS) -o $@ $^ -lrt

tests/test_production_config: $(TEST_PROD_CONFIG_SRC)
	$(CC) $(TEST_PROD_FLAGS) -I/tmp/json-stub -o $@ $^ -ljson-c -lrt

tests/test_production_integ: $(TEST_PROD_INTEG_SRC) 
	$(CC) $(TEST_PROD_FLAGS) -o $@ $^ $(TEST_PROD_LIBS)

tests/test_production_mgmt: $(TEST_PROD_MGMT_SRC)
	$(CC) $(TEST_PROD_FLAGS) -I/tmp/json-stub -o $@ $^ -lrt -lnettle

tests/test_production_api: $(TEST_PROD_API_SRC)
	$(CC) $(TEST_PROD_API_FLAGS) -o $@ $^ $(TEST_PROD_API_LIBS)

test-prod: tests/test_production_crypto tests/test_production_channel tests/test_production_kcp tests/test_production_config tests/test_production_integ tests/test_production_mgmt tests/test_production_api
	@chmod +x tests/test_production_crypto tests/test_production_channel tests/test_production_kcp tests/test_production_config tests/test_production_integ tests/test_production_mgmt tests/test_production_api
	@echo '--- Crypto (130 cases) ---'
	@tests/test_production_crypto; E1=$$?
	@echo ''
	@echo '--- Channel+Proxy (130 cases) ---'
	@tests/test_production_channel; E2=$$?
	@echo ''
	@echo '--- KCP+ACL (100 cases) ---'
	@tests/test_production_kcp; E3=$$?
	@echo ''
	@echo '--- Config+Mgmt (120 cases) ---'
	@tests/test_production_config; E4=$$?
	@echo ''
	@echo '--- Integration (120 cases, best effort) ---'
	@tests/test_production_integ; E5=$$?; \
		echo ''; \
		echo '--- Mgmt Protocol (140 cases) ---'; \
		tests/test_production_mgmt; E6=$$?; \
		echo ''; \
		echo '--- API Endpoints (150 cases) ---'; \
		tests/test_production_api; E7=$$?; \
		echo ''; \
		echo '== Production test suite complete =='; \
		E=$$((E1|E2|E3|E4|E5|E6|E7)); \
		if [ $$E -ne 0 ]; then \
			echo "WARNING: $$E exit(s) failed (E1=$$E1 E2=$$E2 E3=$$E3 E4=$$E4 E5=$$E5 E6=$$E6 E7=$$E7)"; \
		fi; \
		exit $$E

# ── CLI 工具 ──────────────────────────────────────────────────────────
CLI_SRC  := src/cli.c
CLI_BIN  := gapproxy-cli

.PHONY: cli
cli: $(CLI_BIN)

$(CLI_BIN): $(CLI_SRC)
	$(CC) -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -O2 -o $@ $^ -I/tmp/json-stub -ljson-c

clean-cli:
	rm -f $(CLI_BIN)

