
THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

.PHONY: test loop null

test:
	${THIS_DIR}null_001 1 1
	${THIS_DIR}null_001 2 2
	${THIS_DIR}loop_001 1 1
	${THIS_DIR}loop_001 2 2

loop:
	${THIS_DIR}loop_001 1 1
	${THIS_DIR}loop_001 2 2

null:
	${THIS_DIR}null_001 1 1
	${THIS_DIR}null_001 2 2
