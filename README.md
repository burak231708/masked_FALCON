# Masking Falcon

Masked implementation of the FALCON post-quantum signature in C for computers

## Table of Contents
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Structure](#structure)
## Description

This project propose a solution to mask FALCON. This work is based on https://tches.iacr.org/index.php/TCHES/article/view/11428. It is written in C.

## Installation

To install and set up this project on your local machine, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/project-name.git
   ```
   
2. **Install Cmake:**

This section explains how to install **CMake** on a Linux system, in particulary on Ubuntu or Debian.
Ensure you have **sudo** privileges on your system to install software. You'll also need an internet connection to download the necessary packages.

   Open a terminal and run:

   ```bash
   sudo apt update
   sudo apt install cmake
   cmake --version
   ```
   
3. **Run CmakeLists.txt:**
   
In build folder, you have to create **Cmake** context:

   ```bash
   mkdir build
   cd build
   cmake ..
   ```
## Usage

To compile, in build folder :

   ```bash
   make
   ```
After compiling, you can run the project with the following command:

```bash
./name
```
name must be replace by one of the following test : 
- test_utils
- test_gadgets
- test_chenchen_gadgets
- test_chenchen_modify
- test_secfpr
- test_final

## Structure

This work is divided into five sections :
- **utils** : Utility functions.
- **gadgets** : Secure gadgets used by Chen and Chen.
   - SecAnd;
   - SecAdd;
   - SecMul;
   - ...
- **chenchen_gadgets** : Secure gadgets from Chen and Chen.
   - SecNonZero;
   - SecOr;
   - SecFprUrsh;
   - SecFpr;
   - SecFprAdd;
   - SecFprMul.
- **chenchen_modify** : Modified Chen and Chen's gadgets to implement secfpr functions.
- **secfpr** : The main contribution.
   - SecFprFloor;
   - SecFprTrunc;
   - SecFprInv;
   - ApproxExp, BerExp, SamplerZ;
   - ...
