#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build-foxcore"
STAGE_DIR="${BUILD_DIR}/stage"
ARTIFACT_DIR="${BUILD_DIR}/artifacts"
DEPS_DIR="${BUILD_DIR}/.cmake-deps"

INSTALL_PREFIX="/opt/foxcore-krdp"
BUILD_TYPE="RelWithDebInfo"
SKIP_TESTS=0
BUILD_ARCH_PKG=0
JOBS="$(nproc 2>/dev/null || echo 4)"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build KRdp with FOXCORE native AF_VSOCK / Hyper-V Enhanced Session support.

Options:
  --prefix DIR       Target install prefix (default: /opt/foxcore-krdp)
  --build-dir DIR    Out-of-tree build directory (default: ./build-foxcore)
  --build-type TYPE  CMake build type (default: RelWithDebInfo)
  --skip-tests       Skip running ctest after compilation
  --pkg              Also build an Arch/CachyOS .pkg.tar.zst package via makepkg
  -j, --jobs N       Parallel build jobs (default: ${JOBS})
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --build-dir) BUILD_DIR="$2"; STAGE_DIR="${BUILD_DIR}/stage"; ARTIFACT_DIR="${BUILD_DIR}/artifacts"; DEPS_DIR="${BUILD_DIR}/.cmake-deps"; shift 2 ;;
        --build-type) BUILD_TYPE="$2"; shift 2 ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --pkg) BUILD_ARCH_PKG=1; shift ;;
        -j|--jobs) JOBS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

echo "[foxcore-build] Repository root : ${REPO_ROOT}"
echo "[foxcore-build] Build directory : ${BUILD_DIR}"
echo "[foxcore-build] Install prefix  : ${INSTALL_PREFIX}"

for cmd in cmake ninja g++ pkg-config tar zstd sha256sum; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: Required build tool not found: ${cmd}" >&2
        exit 1
    fi
done

CMAKE_PREFIX_ARGS=()
NEED_LOCAL_DEPS=()
[[ -d /usr/share/ECM ]] || NEED_LOCAL_DEPS+=(extra-cmake-modules)
[[ -d /usr/share/plasma-wayland-protocols ]] || NEED_LOCAL_DEPS+=(plasma-wayland-protocols)

if [[ ${#NEED_LOCAL_DEPS[@]} -gt 0 ]]; then
    echo "[foxcore-build] Pure build-data packages missing from /usr (${NEED_LOCAL_DEPS[*]})."
    echo "[foxcore-build] Staging local non-root copy in ${DEPS_DIR} (system untouched)..."
    mkdir -p "${DEPS_DIR}"
    for pkg in "${NEED_LOCAL_DEPS[@]}"; do
        marker="${DEPS_DIR}/.${pkg}.extracted"
        if [[ ! -f "${marker}" ]]; then
            url="$(pacman -Sp "${pkg}" 2>/dev/null | head -n 1 || true)"
            if [[ -z "${url}" ]]; then
                echo "ERROR: Cannot resolve package URL for ${pkg} via pacman -Sp. Install ${pkg} or check network." >&2
                exit 1
            fi
            echo "[foxcore-build] Fetching ${url}"
            curl -fsSL "${url}" | tar --zstd -xf - -C "${DEPS_DIR}"
            touch "${marker}"
        fi
    done
    CMAKE_PREFIX_ARGS+=("-DCMAKE_PREFIX_PATH=${DEPS_DIR}/usr")
fi

# Refresh portable patch file against upstream v6.8.3 tag when inside git repo
if git -C "${REPO_ROOT}" rev-parse --verify v6.8.3 >/dev/null 2>&1; then
    mkdir -p "${SCRIPT_DIR}/patches"
    git -C "${REPO_ROOT}" diff v6.8.3 -- CMakeLists.txt src/ server/ autotests/ \
        > "${SCRIPT_DIR}/patches/0001-foxcore-hyperv-vsock-enhanced-session.patch"
fi

cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DKDE_SKIP_RPATH_SETTINGS=ON \
    -DCMAKE_INSTALL_RPATH="\$ORIGIN/../lib:\$ORIGIN/../lib64" \
    -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=FALSE \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=FALSE \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=OFF \
    "${CMAKE_PREFIX_ARGS[@]}"

cmake --build "${BUILD_DIR}" -j "${JOBS}"

if [[ "${SKIP_TESTS}" -eq 0 ]]; then
    echo "[foxcore-build] Running CTest suite..."
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
fi

# Stage installable side-by-side artifact
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}" "${ARTIFACT_DIR}"
DESTDIR="${STAGE_DIR}" cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"

# Verify staged binary exists and resolves its own libKRdp.so.6 via RUNPATH (never stock /usr/lib)
STAGED_BIN="${STAGE_DIR}${INSTALL_PREFIX}/bin/krdpserver"
if [[ ! -x "${STAGED_BIN}" ]]; then
    echo "ERROR: Staged binary missing: ${STAGED_BIN}" >&2
    exit 1
fi
RESOLVED_LIBKRDP="$(ldd "${STAGED_BIN}" | awk '/libKRdp\.so/ {print $3; exit}')"
echo "[foxcore-build] Staged binary libKRdp resolution: ${RESOLVED_LIBKRDP}"
if [[ "${RESOLVED_LIBKRDP}" != "${STAGE_DIR}${INSTALL_PREFIX}/"* ]]; then
    echo "ERROR: Staged binary resolves libKRdp outside staged prefix (${RESOLVED_LIBKRDP})!" >&2
    exit 1
fi
HELP_OUT="$("${STAGED_BIN}" --help 2>&1)"
if ! grep -q -- "--transport" <<< "${HELP_OUT}"; then
    echo "ERROR: Staged binary self-check (--help --transport) failed!" >&2
    exit 1
fi

VERSION="$(awk -F'"' '/set\(PROJECT_VERSION/ {print $2; exit}' "${REPO_ROOT}/CMakeLists.txt")"
ARCH="$(uname -m)"
ARTIFACT_PATH="${ARTIFACT_DIR}/krdp-foxcore-${VERSION}-${ARCH}.tar.zst"

tar --zstd -cf "${ARTIFACT_PATH}" -C "${STAGE_DIR}${INSTALL_PREFIX}" .
(cd "${ARTIFACT_DIR}" && sha256sum "$(basename "${ARTIFACT_PATH}")" > "$(basename "${ARTIFACT_PATH}").sha256")

echo "[foxcore-build] Artifact created: ${ARTIFACT_PATH}"
cat "${ARTIFACT_PATH}.sha256"

if [[ "${BUILD_ARCH_PKG}" -eq 1 ]]; then
    echo "[foxcore-build] Building Arch/CachyOS package via makepkg..."
    PKG_WORK="${BUILD_DIR}/archpkg"
    rm -rf "${PKG_WORK}"
    mkdir -p "${PKG_WORK}"
    cp "${SCRIPT_DIR}/PKGBUILD" "${PKG_WORK}/PKGBUILD"
    cp "${SCRIPT_DIR}/systemd/app-org.kde.krdpserver-vsock.service" "${PKG_WORK}/"
    (
        cd "${PKG_WORK}"
        FOXCORE_SRC_DIR="${REPO_ROOT}" FOXCORE_CMAKE_DEPS="${DEPS_DIR}/usr" makepkg -f --nodeps
    )
    cp "${PKG_WORK}"/*.pkg.tar.zst "${ARTIFACT_DIR}/"
    echo "[foxcore-build] Arch package copied to ${ARTIFACT_DIR}/"
fi

echo "[foxcore-build] Build completed successfully."
