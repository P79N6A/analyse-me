
include Makefile.mk

BUILD_DIR   :=$(CURDIR)/build_dir
INSTALL_DIR :=$(CURDIR)/_install
		

SOURCE_C = $(foreach dir, $(SOURCE_DIR), $(wildcard $(dir)/*.c))
OBJECES  = $(SOURCE_C:.c=.o)
		
	
INCLUDE_PATH = $(shell find $(CURDIR)  -maxdepth 16 -type d | grep "include")
INCLUDE_DIR  += $(foreach dir, $(INCLUDE_PATH), -I$(dir))

export BUILD_DIR INCLUDE_DIR INSTALL_DIR CC AR LD STRIP CFLAGS LDFLAGS TARGET_LIB TARGET_APP

.PHONY : all clean install

all:$(OBJECES)

	@echo "-----------------build start-----------------------"
	@rm -rf $(BUILD_DIR)
	@rm -rf $(INSTALL_DIR)
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(INSTALL_DIR)

	@mv $(OBJECES) $(BUILD_DIR)
	$(CC)  $(BUILD_DIR)/*.o $(LDFLAGS)  -o $(INSTALL_DIR)/$(TARGET_APP)
	$(STRIP) $(INSTALL_DIR)/$(TARGET_APP)
	@echo "-----------------build end-----------------------"

$(OBJECES):%.o:%.c   
	@echo "-----------------compile src start-----------------------"
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c $< -o $@
	@echo "-----------------compile src end-----------------------"
clean:
	@-rm -rf $(BUILD_DIR)
	@-rm -rf $(INSTALL_DIR)

install:
	@echo "Nothing to do"
	cp $(INSTALL_DIR)/$(TARGET_APP)  $(INSTALL_BIN)
	cp config/* $(INSTALL_CONFIG)