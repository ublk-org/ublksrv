# SPDX-License-Identifier: MIT or GPL-2.0-only

THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

.PHONY: run clean

run:
	${THIS_DIR}/run_test.sh ${THIS_DIR}${T} ${R} ${C}

clean:
	find ${THIS_DIR} -name "*~" | xargs rm -f
