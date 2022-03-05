# Needham-Schroeder Scheme Implementation

*Author: Franklin Yuan*

## Installation

Install the `PyCrypto` library with:

```
pip install pycryptodome
```

## How the code is organized

Each of the four parties have their own individual programs: `alice.py`, `bob.py`, `kdc.py`, and `trudy.py`.

Program parameters (such as which protocol and cipher mode to use) can be set in `params.py`. A few other constants are defined there as well.

Helper functions used by all parties are found in `utils.py`.

## How to run the code

To run the code, first set the program parameters in `params.py`. Then, open three terminals:

* Terminal 1: run `python bob.py`
* Terminal 2: run `python kdc.py`
* Terminal 1: run `python alice.py`, followed by `python trudy.py` when testing the original Needham-Schroeder Scheme

## Output and debug files

The output of print statements can be found in either the `output` directory (when debug is turned off) or the `debug` directory (when debug is turned on).