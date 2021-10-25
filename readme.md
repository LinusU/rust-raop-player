# Rust RAOP Player

This is an AirPlay player for the RAOP v2 protocol with synchronization. It's largely a port of [philippe44/RAOP-Player](https://github.com/philippe44/RAOP-Player).

I've tested this on macOS `x86_64` & Linux `mipsel` (Onion Omega2), but it _should_ work on [any platform that Rust supports](https://forge.rust-lang.org/release/platform-support.html).

## Installation

You can install the latest commit directly from git on your current machine with the following command:

```sh
cargo install --force --git https://github.com/LinusU/rust-raop-player
```

## Usage

```text
Usage:
    raop_play [options] <server-ip> <filename>
    raop_play (-h | --help)

Options:
    -a            Send ALAC compressed audio
    -d LEVEL      Debug level (0 = silent, 5 = trace) [default: 2]
    -e            Encrypt AirPlay stream using RSA
    -h, --help    Print this help and exit
    -l LATENCY    Latency in frames [default: 44100]
    -p PORT       Specify remote port [default: 5000]
    -v VOLUME     Specify volume between 0 and 100 [default: 50]
    -t ET         et-field in mDNS - used to detect MFi
    -m MD         md in mDNS: metadata capabilties 0=text, 1=artwork, 2=progress
```
