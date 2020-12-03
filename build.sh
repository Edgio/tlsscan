#!/bin/bash

# ------------------------------------------------------------------------------
# Usage
# ------------------------------------------------------------------------------
usage() {
	cat <<EOM
$0: [hs]
	-h display some help, you know, this
	-s shallow clone, useful for faster builds
	-p install prefix

-s doesn't work with git prior to 2.8 (e.g. xenial)
EOM
	exit 1
}

# ------------------------------------------------------------------------------
# Requirements to build...
# ------------------------------------------------------------------------------
check_req() {
	which cmake g++ make || {
		echo "Failed to find required build packages. Please install with: sudo apt-get install cmake make g++"
		exit 1
	}
}
# ------------------------------------------------------------------------------
# submodule sync
# ------------------------------------------------------------------------------
submod_sync() {
	git submodule sync || {
		echo "FAILED TO SYNC SUBMODULES"
		exit 1
	}
}
# ------------------------------------------------------------------------------
# submodule update - We only need a shallow clone
# ------------------------------------------------------------------------------
submod_update() {
	if [[ "$1" == "true" ]]; then
		git submodule update -f --init --depth 1 || {
			echo "FAILED TO UPDATE TO LATEST (SHALLOW) SUBMODULES"
			exit 1
		}
	else
		git submodule update -f --init || {
			echo "FAILED TO UPDATE TO LATEST SUBMODULES"
			exit 1
		}
	fi
}

# ------------------------------------------------------------------------------
# build...
# ------------------------------------------------------------------------------
main() {
	check_req
	submod_sync
	submod_update "${shallow_clone}"
	mkdir -p build
	pushd build && \
		cmake ../ \
		-DBUILD_SYMBOLS=ON \
		-DCMAKE_INSTALL_PREFIX=${install_prefix} && \
		make -j${NPROC} && \
		umask 0022 && chmod -R a+rX . && \
		make package && \
		popd && \
	exit $?
}

#set shallow to false
shallow_clone="false"
install_prefix="/usr"

#parse options
while getopts ":hsp:" opts; do
	case "${opts}" in
		h)
			usage
			;;
		s)
			shallow_clone="true"
			;;
		p)
			install_prefix="${OPTARG}"
			;;
		*)
			usage
			;;
	esac
done

main
