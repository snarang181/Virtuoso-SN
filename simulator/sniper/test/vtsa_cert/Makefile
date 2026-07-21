# Standalone build for the V-TSA certificate-manager conformance suite.
# No Sniper dependencies by design (see cert_manager.h).
CXX ?= g++
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -fsanitize=address,undefined

CERT_DIR := ../../common/system/memory_management/certificates

test_cert_conformance: test_cert_conformance.cc fake_vspace.h \
		$(CERT_DIR)/cert_manager.cc $(CERT_DIR)/cert_manager.h \
		$(CERT_DIR)/address_space_view.h
	$(CXX) $(CXXFLAGS) -I$(CERT_DIR) test_cert_conformance.cc \
		$(CERT_DIR)/cert_manager.cc -o $@

test_cert_rlb: test_cert_rlb.cc fake_vspace.h \
		$(CERT_DIR)/cert_manager.cc $(CERT_DIR)/cert_manager.h \
		$(CERT_DIR)/cert_rlb.h $(CERT_DIR)/address_space_view.h
	$(CXX) $(CXXFLAGS) -I$(CERT_DIR) test_cert_rlb.cc \
		$(CERT_DIR)/cert_manager.cc -o $@

.PHONY: run clean
run: test_cert_conformance test_cert_rlb
	./test_cert_conformance
	./test_cert_rlb

clean:
	rm -f test_cert_conformance test_cert_rlb
