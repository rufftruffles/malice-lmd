####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

COPY . /build/lmd/
WORKDIR /build/lmd

# Pure Go (shells out to the maldet CLI) -> static binary.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan .

####################################################
# LMD RUNTIME
####################################################
# maldet is a bash script that depends on the GNU userland (GNU date -d,
# readlink -f, mawk). Alpine's busybox is hostile to it, so a Debian/
# Ubuntu base is used. ubuntu:22.04 is a clean, minimal base for bash CLI
# tools and is already cached on the build host.
FROM ubuntu:22.04

LABEL maintainer="https://github.com/malice-plugins"

LABEL malice.plugin.repository="https://github.com/malice-plugins/lmd.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

ENV LMD_VERSION=2.0.1
ENV DEBIAN_FRONTEND=noninteractive
# Ensure the maldet CLI (/usr/local/sbin/maldet) is on PATH for the scan
# binary's exec calls.
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# maldet is bash + GNU userland: bash, coreutils (date -d, readlink -f,
# sha256sum, stat), curl (signature download), ca-certificates (HTTPS),
# gzip/tar (signature pack), findutils/grep/sed (file listing + parsing),
# mawk (the awk dialect maldet targets), util-linux (flock).
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       bash coreutils curl ca-certificates gzip tar findutils grep sed mawk util-linux \
  && rm -rf /var/lib/apt/lists/*

# Install maldet v2.0.1 at build time. The v2.0.1 tarball is published as a
# GitHub release (rfxn.com's "current" tarball is 1.6.6). install.sh must
# be run with bash (it uses bashisms: source, [[ ]]). install.sh downloads
# the signature DB from cdn.rfxn.com, so the build needs network access.
RUN curl -fsSL -o /tmp/maldet.tgz \
       "https://github.com/rfxn/linux-malware-detect/releases/download/v${LMD_VERSION}/maldet-${LMD_VERSION}.tar.gz" \
  && mkdir -p /tmp/lmd \
  && tar xzf /tmp/maldet.tgz -C /tmp/lmd --strip-components=1 \
  && cd /tmp/lmd && bash install.sh \
  && rm -f /tmp/maldet.tgz && rm -rf /tmp/lmd

# The malice core stages samples as root-owned files under /malware and the
# container runs as root. maldet's default scan_ignore_root="1" would skip
# every root-owned file (yielding an empty scan), so disable it.
#
# maldet's default scan_max_filesize="2048k" (2MB) is tuned for scanning
# trees of small web files. Malice submits a single sample of arbitrary size,
# and the SHA-256 hash pass should cover the whole file (the hex/CSIG pass is
# already bounded by scan_hexdepth=256KB), so raise the cap to 10GB.
RUN sed -i "s/^scan_ignore_root=.*/scan_ignore_root=\"0\"/" /usr/local/maldetect/conf.maldet \
  && sed -i "s/^scan_max_filesize=.*/scan_max_filesize=\"10240M\"/" /usr/local/maldetect/conf.maldet

# Quarantine is already disabled by default (quarantine_hits="0"), so a scan
# never mutates the staged sample.

COPY --from=go_builder /bin/scan /bin/scan

WORKDIR /malware

ENTRYPOINT ["scan"]
CMD ["--help"]
