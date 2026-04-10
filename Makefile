# Makefile for Capstone — Kernel Rootkit + Exploitation
#
# Each subdirectory has its own Makefile. This top-level Makefile just
# delegates. Students add code in lkm/, exploit/, loader/, and shellcode/.
#
# Components:
#   lkm/           Kernel rootkit module (student code)
#   exploit/       Privilege escalation programs (student code)
#   loader/        Reflective loader (student code)
#   shellcode/     Beachhead PIC shellcode (student code)
#   tools/         C2 helpers (provided)
#   drivers/       Vulnerable kernel drivers (provided, reference)
#   service/       MERIDIAN TCP service (provided, reference)
#
# Usage:
#   make               — build all components
#   make lkm           — build rootkit.ko
#   make exploit        — build exploit programs
#   make loader         — build reflective loader
#   make shellcode      — assemble beachhead shellcode
#   make tools          — build mykill, rkcmd
#   make deploy         — copy everything to QEMU shared folder
#   make run            — boot dev VM with shared folder (interactive)
#   make target         — boot target VM black-box mode
#   make test           — deploy, boot fresh VM, run test harness, report
#   make setup-kernel   — download + extract kernel headers tarball
#   make setup-target   — download QCOW2 + Image
#   make clean          — remove all build artifacts

include config.mk

# Default: build everything
all: lkm exploit loader shellcode tools

lkm:
	$(MAKE) -C lkm

exploit:
	$(MAKE) -C exploit

loader:
	$(MAKE) -C loader

shellcode:
	$(MAKE) -C shellcode

tools:
	$(MAKE) -C tools

clean:
	$(MAKE) -C lkm clean
	$(MAKE) -C exploit clean
	$(MAKE) -C loader clean
	$(MAKE) -C shellcode clean
	$(MAKE) -C tools clean

# ── Deploy to QEMU shared folder ─────────────────────────────────────────────

deploy: all
	@echo ">>> Deploying to $(SHARED)/capstone..."
	@mkdir -p $(SHARED)/capstone
	cp -f lkm/rootkit.ko                     $(SHARED)/capstone/ 2>/dev/null || true
	cp -f tools/mykill                        $(SHARED)/capstone/ 2>/dev/null || true
	cp -f tools/rkcmd                         $(SHARED)/capstone/ 2>/dev/null || true
	cp -f tools/inject_test.bin               $(SHARED)/capstone/ 2>/dev/null || true
	cp -f shellcode/*.bin                     $(SHARED)/capstone/ 2>/dev/null || true
	cp -f exploit/exploit_*                   $(SHARED)/capstone/ 2>/dev/null || true
	cp -f loader/loader                       $(SHARED)/capstone/ 2>/dev/null || true
	cp -f test/test_lkm.sh                    $(SHARED)/capstone/ 2>/dev/null || true
	cp -f test/test_challenges.sh             $(SHARED)/capstone/ 2>/dev/null || true
	cp -f test/test_chain.sh                  $(SHARED)/capstone/ 2>/dev/null || true
	cp -f tools/send_shellcode.py             $(SHARED)/capstone/ 2>/dev/null || true
	cp -f service/snitch/snitch.ko            $(SHARED)/capstone/ 2>/dev/null || true
	cp -f service/snitch/snitch_watcher       $(SHARED)/capstone/ 2>/dev/null || true
	cp -f service/snitch/snitch-watcher.service $(SHARED)/capstone/ 2>/dev/null || true
	@echo ">>> Deploy complete. In the VM:"
	@echo ">>>   mount-shared"
	@echo ">>>   cd /mnt/shared/capstone"

# ── VM launch (disposable overlays — golden QCOW2 is never modified) ─────────

run: deploy
	bash target/start-dev.sh

run-persist: deploy
	bash target/start-dev.sh --persist

target:
	bash target/start-target.sh

target-persist:
	bash target/start-target.sh --persist

# ── Testing ──────────────────────────────────────────────────────────────────

test: deploy
	bash test/run_tests.sh

# ── Individual test targets (run inside VM, require root) ────────────────────
# These are for interactive use after 'make run' gets you a shell in the VM.

test-lkm:
	sudo bash test/test_lkm.sh

test-lkm-%:
	sudo bash test/test_lkm.sh $*

test-challenges:
	sudo bash test/test_challenges.sh

test-chain:
	sudo bash test/test_chain.sh

test-chain-%:
	sudo bash test/test_chain.sh $*

# ── Overlay management ───────────────────────────────────────────────────────

overlay:
	@echo ">>> Creating fresh overlay..."
	@rm -f target/.dev-overlay.qcow2
	qemu-img create -f qcow2 -F qcow2 \
		-b capstone-target.qcow2 target/.dev-overlay.qcow2
	@echo ">>> Done. Use 'make run-persist' to boot it."

clean-overlay:
	rm -f target/.dev-overlay.qcow2 target/.target-overlay.qcow2 target/.test-overlay.qcow2

# ── WireGuard ────────────────────────────────────────────────────────────────

wg-gen:
	cd wireguard && bash gen_configs.sh

wg-set-endpoint:
	@if [ -z "$(IP)" ]; then echo "Usage: make wg-set-endpoint IP=1.2.3.4"; exit 1; fi
	@echo ">>> Setting endpoint to $(IP):51820 in all client configs..."
	@sed -i 's/<SERVER_PUBLIC_IP>/$(IP)/g' wireguard/clients/group-*.conf 2>/dev/null || true
	@echo ">>> Done. Distribute wireguard/clients/group-NN.conf to each group."

wg-up:
	sudo wg-quick up wg0

wg-down:
	sudo wg-quick down wg0

wg-status:
	sudo wg show

# ── Asset setup (download kernel headers and target images) ──────────────────

ASSET_URL ?= https://courses.example.edu/capstone/assets

setup-kernel:
	@echo ">>> Setting up kernel headers..."
	@if [ -d kernel/linux-6.6 ]; then \
		echo "    kernel/linux-6.6/ already exists"; \
	else \
		echo "    Download linux-6.6-headers.tar.gz and extract:"; \
		echo "      curl -L $(ASSET_URL)/linux-6.6-headers.tar.gz -o /tmp/headers.tar.gz"; \
		echo "      tar xzf /tmp/headers.tar.gz -C kernel/"; \
		echo "    Or symlink from your lab:"; \
		echo "      ln -s ~/teaching/aarch64-linux-qemu-lab/linux-6.6 kernel/linux-6.6"; \
	fi

setup-target:
	@echo ">>> Setting up target VM..."
	@if [ -f target/capstone-target.qcow2 ] && [ -f target/Image ]; then \
		echo "    Target assets already present"; \
	else \
		echo "    Download capstone-assets.tar.gz and extract:"; \
		echo "      curl -L $(ASSET_URL)/capstone-assets.tar.gz -o /tmp/assets.tar.gz"; \
		echo "      tar xzf /tmp/assets.tar.gz -C target/"; \
		echo "    Or symlink from your lab:"; \
		echo "      ln -s ~/teaching/aarch64-linux-qemu-lab/linux-6.6/arch/arm64/boot/Image target/Image"; \
	fi

# ── Convenience targets (run inside QEMU VM, require root) ──────────────────

load:
	sudo insmod lkm/rootkit.ko

unload:
	sudo rmmod rootkit

reload: unload load

log:
	sudo dmesg | tail -40

status:
	@echo "=== LKM ==="
	@lsmod | grep rootkit || echo "rootkit module is not loaded"
	@echo ""
	@echo "=== C2 test ==="
	@kill -62 0 2>/dev/null && echo "C2 channel active" || echo "C2 channel not active"

# ── Submission ───────────────────────────────────────────────────────────────

submission.zip:
	zip -r submission.zip \
		lkm/src/ lkm/Makefile \
		exploit/ loader/ shellcode/ \
		writeup/ \
		Makefile config.mk \
		--exclude '*.gitkeep'

.PHONY: all lkm exploit loader shellcode tools clean deploy \
	run run-persist target target-persist \
	test test-lkm test-challenges test-chain \
	overlay clean-overlay \
	wg-gen wg-set-endpoint wg-up wg-down wg-status \
	setup-kernel setup-target \
	load unload reload log status
