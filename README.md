# hbctool 

[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://python.org) [![PyPI version](https://badge.fury.io/py/hbctool.svg)](https://badge.fury.io/py/hbctool) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](/LICENSE)

> **Fork note:** this is a fork of [Kirlif/HBC-Tool](https://github.com/Kirlif/HBC-Tool)
> (itself a fork of [bongtrop/hbctool](https://github.com/bongtrop/hbctool)), rebased onto
> Kirlif's HBC 97/98/99 support, with a few fixes on top:
> - shrinking a string now truncates its stored length instead of leaving old bytes behind
> - editing a string no longer gets reverted when another string shares its storage
> - on HBC 97+, a function that doesn't survive a disassemble/reassemble round trip is left untouched instead of getting corrupted
> - a bad string index or function name no longer crashes disasm
> - `Double` operands are written as exact little-endian bytes, and old decimal `.hasm` dumps still load

A command-line interface for disassembling and assembling the Hermes Bytecode.

Since the React Native team created their own JavaScript engine (named Hermes) for running the React Native application, the JavaScript source code is often compiled to the Hermes bytecode. In the penetration test project, I found that some React Native applications have already been migrated to the Hermes engine. It is really head for me to analyze or patch those applications. Therefore, I created hbctool for helping any pentester to test the Hermes bytecode.

> [Hermes](https://hermesengine.dev/) is an open-source JavaScript engine optimized for running React Native apps on Android. For many apps, enabling Hermes will result in improved start-up time, decreased memory usage, and smaller app size. At this time Hermes is an opt-in React Native feature, and this guide explains how to enable it.


## Installation

To install hbctool, simply use pip:

```
pip install --force-reinstall hbctool-0.1.6-py3-none-any.whl
```

## Usage

Please run `hbctool --help` to show the usage.

```
hbctool --help   
A command-line interface for disassembling and assembling
the Hermes Bytecode.

Usage:
    hbctool disasm <HBC_FILE> <HASM_PATH>
    hbctool asm <HASM_PATH> <HBC_FILE>
    hbctool --help
    hbctool --version

Operation:
    disasm              Disassemble Hermes Bytecode
    asm                 Assemble Hermes Bytecode

Args:
    HBC_FILE            Target HBC file
    HASM_PATH           Target HASM directory path

Options:
    --version           Show hbctool version
    --help              Show hbctool help manual

Examples:
    hbctool disasm index.android.bundle test_hasm
    hbctool asm test_hasm index.android.bundle
```

> For Android, the HBC file normally locates at `assets` directory with `index.android.bundle` filename.

## Support

hbctool currently supports the following Hermes Bytecode version:

- [Hermes Bytecode version 59]
- [Hermes Bytecode version 62]
- [Hermes Bytecode version 74]
- [Hermes Bytecode version 76]
- [Hermes Bytecode version 83]
- [Hermes Bytecode version 84]
- [Hermes Bytecode version 85]
- [Hermes Bytecode version 86]
- [Hermes Bytecode version 87]
- [Hermes Bytecode version 88]
- [Hermes Bytecode version 89]
- [Hermes Bytecode version 90]
- [Hermes Bytecode version 91]
- [Hermes Bytecode version 92]
- [Hermes Bytecode version 93]
- [Hermes Bytecode version 94]
- [Hermes Bytecode version 95]
- [Hermes Bytecode version 96]
- [Hermes Bytecode version 97]
- [Hermes Bytecode version 98]
- [Hermes Bytecode version 99]
