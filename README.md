# Workbook for Introduction to Programmable Cryptography

## Notes

The main objective of the code is to help readers follow the book and its concepts. Thus the code is written in the simplest and most straight forward manner possible (i.e. no optimizations).

TODO: remove `.py` files as they are for dev purposes and are replicates of `.ipynb`

## How To Install

### Dependencies

This project's dependencies are managed by [Poetry](https://python-poetry.org/).

#### Install Poetry (if not already installed)

```shell
pipx install poetry
```

If the above doesn't work for you, you can see see additional instructions [here](https://python-poetry.org/docs/#installation) on Poetry installation.

#### Install Dependencies with Poetry

```shell
poetry install
```

## How To Run

All notebook files are in the `src` folder and can be run inside a Jupyter Lab environment.

To start JupyterLab:

``` bash
jupyter-lab
```

Then open the jupyter notebook files inside the `\src` folder


## How to Test

There are unittest files for certain chapters.

**Run all test files:**

```bash
poetry run pytest
```

**Run test for specifc chapter:**

```bash
poetry run pytest tests/test_ch_6_oram.py
```

## Roadmap

- [ ] Code companion to text
  - [ ] Ch 2: 2PC
    - [x] 2.1.3 Garbled gates
    - [x] 2.1.4 Chaining garbled gates
    - [x] 2.1.5 How Bob uses one gate
    - [x] 2.2.1 Commutative encryption
    - [ ] 2.2.3 OT in one step
    - [x] 2.1.5 Chaining multiple gates
    - [x] Combine garbled circuits and OT
  - [ ] Ch 3: EC & PCS
    - [x] 3.2.2 EdDSA Signature Scheme
    - [x] 3.2.3 Pedersen Commitments
    - [x] 3.4 KZG Commitments
  - [ ] Ch 4: SNARKs
  - [ ] Ch 5: FHE
    - [x] 5.3 Public Key Cryptography from LWE Example
    - [x] 5.4.3 The "Flatten" Operation
  - [ ] Ch 6: ORAM
    - [x] 6.3 Binary Tree ORAM
    - [x] 6.7 Path ORAM
    - Other Ideas:
      - [ ] 6.6 Recursive ORAM
      - [ ] Encryption and decryption on blocks
- [ ] Exercises
