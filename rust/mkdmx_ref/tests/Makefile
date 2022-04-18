.PHONY: all images clean old

# ------------------------------------------------------------------------------------------------------#
MKMINT_PATH = ../../../c/code/mkmint/mkmint

IMG_LOOP_0 = "loop_0.img"
IMG_LOOP_1 = "loop_1.img"

IMG_RAND_0 = "rand_0.img"
IMG_RAND_1 = "rand_1.img"

IMG_OLD_0 = "old_0.img"
IMG_OLD_1 = "old_1.img"
IMG_OLD_2 = "old_2.img"

SAME = $(shell losetup -j $(IMG_OLD_0) | awk {'print $$1'} | tr -d ':')
META = $(shell losetup -j $(IMG_OLD_1) | awk {'print $$1'} | tr -d ':')
DATA = $(shell losetup -j $(IMG_OLD_2) | awk {'print $$1'} | tr -d ':')


IMAGES = $(IMG_LOOP_0) $(IMG_LOOP_1) $(IMG_RAND_0) $(IMG_RAND_1) $(IMG_OLD_0) $(IMG_OLD_1) $(IMG_OLD_2)
# ------------------------------------------------------------------------------------------------------#
DEV_LOOP_1_SIZE = 500000000
DEV_LOOP_2_SIZE = 1000000000

DEV_RAND_0_SIZE = 500000000
DEV_RAND_1_SIZE = 1000000000

DEV_OLD_0_SIZE = 1000000000
DEV_OLD_1_SIZE = 500000000
DEV_OLD_2_SIZE = 1000000000


BLOCK_SIZE = 512
BLOCK_SIZE_OLD = 4096

# ------------------------------------------------------------------------------------------------------#
all: clean loop_0 loop_1 rand_0 rand_1 old own

images: $(IMAGES)

old: old_0 old_1 old_2

# ------------------------------------------------------------------------------------------------------#
loop_0: $(IMG_LOOP_0)
	sudo losetup -fP $(IMG_LOOP_0)

$(IMG_LOOP_0):
	dd if=/dev/zero of=$(IMG_LOOP_0) bs=${BLOCK_SIZE} count=$$(( ${DEV_LOOP_1_SIZE} / ${BLOCK_SIZE} ))

loop_1: $(IMG_LOOP_1)
	sudo losetup -fP $(IMG_LOOP_1)

$(IMG_LOOP_1):
	dd if=/dev/zero of=$(IMG_LOOP_1) bs=${BLOCK_SIZE} count=$$(( ${DEV_LOOP_2_SIZE} / ${BLOCK_SIZE} ))

# ------------------------------------------------------------------------------------------------------#
rand_0: $(IMG_RAND_0)
	sudo losetup -fP $(IMG_RAND_0)

$(IMG_RAND_0):
	dd if=/dev/random of=$(IMG_RAND_0) bs=$(BLOCK_SIZE) count=$$(( ${DEV_RAND_0_SIZE} / ${BLOCK_SIZE} ))

rand_1: $(IMG_RAND_1)
	sudo losetup -fP $(IMG_RAND_1)

$(IMG_RAND_1):
	dd if=/dev/random of=$(IMG_RAND_1) bs=$(BLOCK_SIZE) count=$$(( ${DEV_RAND_1_SIZE} / ${BLOCK_SIZE} ))

# ------------------------------------------------------------------------------------------------------#
old_0: $(IMG_OLD_0)
	sudo losetup -fP $(IMG_OLD_0)

$(IMG_OLD_0):
	dd if=/dev/random of=$(IMG_OLD_0) bs=$(BLOCK_SIZE_OLD) count=$$(( ${DEV_OLD_0_SIZE} / ${BLOCK_SIZE_OLD} ))

old_1: $(IMG_OLD_1)
	sudo losetup -fP $(IMG_OLD_1)

$(IMG_OLD_1):
	dd if=/dev/random of=$(IMG_OLD_1) bs=$(BLOCK_SIZE_OLD) count=$$(( ${DEV_OLD_1_SIZE} / ${BLOCK_SIZE_OLD} ))

old_2: $(IMG_OLD_2)
	sudo losetup -fP $(IMG_OLD_2)

$(IMG_OLD_2):
	dd if=/dev/random of=$(IMG_OLD_2) bs=$(BLOCK_SIZE_OLD) count=$$(( ${DEV_OLD_2_SIZE} / ${BLOCK_SIZE_OLD} ))

# ------------------------------------------------------------------------------------------------------#
own:
	sudo chown $(USER) $(shell losetup -j $(IMG_LOOP_0) | awk {'print $$1'} | tr -d ':')
	sudo chown $(USER) $(shell losetup -j $(IMG_LOOP_1) | awk {'print $$1'} | tr -d ':')
	sudo chown $(USER) $(shell losetup -j $(IMG_RAND_0) | awk {'print $$1'} | tr -d ':')
	sudo chown $(USER) $(shell losetup -j $(IMG_RAND_1) | awk {'print $$1'} | tr -d ':')
# ------------------------------------------------------------------------------------------------------#
old: $(IMG_OLD_0) $(IMG_OLD_1)
	$(MAKE) -C ../../../c/code/mkmint
	sudo chown $(USER) $(shell losetup -j $(IMG_OLD_0)  | awk {'print $$1'} | tr -d ':')
	sudo chown $(USER) $(shell losetup -j $(IMG_OLD_1)  | awk {'print $$1'} | tr -d ':')
	sudo chown $(USER) $(shell losetup -j $(IMG_OLD_2)  | awk {'print $$1'} | tr -d ':')
	$(MKMINT_PATH) $(SAME) $(SAME) $(BLOCK_SIZE_OLD) 512 sha256 00 sha256 00 lazy full
	$(MKMINT_PATH) $(META) $(DATA) $(BLOCK_SIZE_OLD) 512 sha256 00 sha256 00 lazy full

# ------------------------------------------------------------------------------------------------------#
clean:
	-@sudo losetup -d $(shell losetup -j $(IMG_LOOP_0) | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_LOOP_1) | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_RAND_0) | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_RAND_1) | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_OLD_0)  | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_OLD_1)  | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@sudo losetup -d $(shell losetup -j $(IMG_OLD_2)  | awk {'print $$1'} | tr -d ':') 2>/dev/null || true
	-@rm $(IMAGES) 2>/dev/null || true

# clean_for:
# 	for image in $(IMAGES) ; do \
# 		im = $(shell losetup -j $$image | awk {'print $$1'} | tr -d ':'); \
#    		-@sudo losetup -d $$im true; \
# 	done
