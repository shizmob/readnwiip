# read'n'wiip

A set of tools to deal with Wii low-level boot and storage.

## Setup

1. Make sure you have Python 3.9+ (for [PEP 585](https://peps.python.org/pep-0585/) support) and `/bin/sh`;
2. `git clone --recursive https://github.com/Shizmob/readnwiip`
3. `pip install -r requirements.txt`

## Usage

* `tweezer.py`: tool to deal with precision items and to bridge checks (Wii cryptography and signing);
* `tong.py`: tool to deal with nasty ticks (Wii ticket, titles and title metadata);
* `texel.py`: tool to deal with Wadden islands (Wii .wad files);
* `tsoprocky.py`: tool to deal with TSOP chips (Wii NAND data);

Refer to the `--help` output of the individual tools, and `./scripts` for some example scripts.

## License

Refer to [`LICENSE`](./LICENSE).
