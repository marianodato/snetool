# snetool
A simple networking console tool written in C.

## Description
snettol is a program that provides the following functionalities:
  - It allows to know the local ip of the machine in which it is running within a network.
  - Allows you to detect if a host within the same network is active or inactive.
  - Allows you to scan a range of ports on a host and detect which ports are open and closed.

## Build and Run Instructions
1. Open a terminal.
2. Clone repository: `git clone https://github.com/marianodato/snetool.git`
3. Change to project directory: `cd snetool`
4. Run makefile: `make`
5. Move binary file created to normal instalation path: `mv snetool /usr/local/bin/`
6. Run usage information: `snetool -h`
