# sssteg

A tool for hiding secrets across multiple files.

It splits up to 1024 bits of secret data and embeds it in JPEG files in a way that a specified number (threshold) of shares are required to recover it. You can further secure the data with a password.

For example, you can use it to store a master password or an encryption key. You hand out the cover files out to unsuspecting friends or upload them to online storage. Without the password, it theoretically should not be possible to identify hidden data. Visually, the cover files remain unchanged.

It is a simple tool implemented in POSIX shell, wrapping two utilities, [ssss](http://point-at-infinity.org/ssss) (uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) algorithm) and [steghide](http://steghide.sourceforge.net/) (does [steganography](https://en.wikipedia.org/wiki/Steganography).

An [AUR package](https://aur.archlinux.org/packages/sssteg/) is available.

## Requirements

### Arch Linux

To run it from source, get the following packages from AUR:
* [ssss](https://aur.archlinux.org/packages/ssss)
* [steghide](https://aur.archlinux.org/packages/steghide)

### Fedora

    # dnf install ssss steghide

### Debian

    # apt-get install ssss steghide

## Features

Provided you are using the latest available versions, ssss 0.5 and steghide 0.5.1:
* Hides up to 1024 bits of data (for larger secrets, encrypt it with a symmetric cipher and hide the encryption key)
* Embeds the secret into JPEG, BMP, WAV and AU files
* Protects the secret with a passphrase
* Theoretically undiscoverable

## Usage

```
sssteg hide    [-q] [-n] [-p <password>] [-s <secret> | -f <secret-file>] [-l <label>] [-t <threshold>] <cover-file> <cover-file>...
sssteg restore [-q] [-n] [-p <password>] [-t <threshold>] [-o <output-file>] [-l <label>]  <stego-file> <stego-file>...
sssteg help | -h
sssteg version | -v

Options:
  -p <password>       Password to protect the data in cover files with [default: ask]
  -s <secret>         Hide this string of <=128 bytes [default: ask]
  -f <secret-file>    Hide this file containing <= 128 bytes
  -l <label>          Textual label to help identify the secret
  -t <threshold>      Number of cover files needed to restore the secret [default: all]
  -o <output-file>    File to restore the secret into [default: stdout]
  -q                  Silence all messages to stdout, except the result
  -n                  Non-interactive: fail if user input is needed
  -h                  Print this message
  -v                  Print version

For an in-depth description of all options, view man page sssteg(1).
```

For more in-depth documentation, consult the [manual page](sssteg.1).

## The name?

`ssss` + `steghide`, but `hide` is redundant and 3 's' characters are just enough.
