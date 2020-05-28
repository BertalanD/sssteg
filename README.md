# sssteg

A tool for hiding secrets across multiple files.

It splits up to 1024 bits of secret data and embeds it in JPEG files in a way that a specified number (threshold) of shares are required to recover it. You can further secure the data with a password.

It is a simple tool, wrapping two utilities, [ssss](http://point-at-infinity.org/ssss) (uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) algorithm) and [steghide](http://steghide.sourceforge.net/) (does [steganography](https://en.wikipedia.org/wiki/Steganography).

## Requirements

### Arch Linux

Get the following packages from AUR:
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
  sssteg hide [-p <password>] [-l <label>] [-s <secret> | -f <secret-file>] [-t <threshold>] <cover-file>...
  sssteg restore [-q] [-p <password>] [-l <label>] [-o <output-file>] [-t <threshold>] <stego-file>...
  sssteg -h

Options:
  -p <password>       Password to protect data in cover files with
                      [default: ask]
  -l <label>          Textual label to help identify the secret
  -s <secret>         Hide this string of <=128 bytes [default: stdin]
  -f <secret-file>    Hide this file containing <= 128 bytes
  -t <threshold>      Number of cover files needed to restore the secret
                      [default: all]
  -o <output-file>    File to restore the secret into [default: stdout]
  -q                  Silence all outputs to stdout, except the result
  -h                  Print this message
```

For more in-depth documentation, consult the [manual page](sssteg.1).

## The name?

`ssss` + `steghide`, but `hide` is redundant and 3 's' characters are just enough.
