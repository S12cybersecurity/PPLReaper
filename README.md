# PPLReaper
PPLReaper is a Windows kernel driver + userland companion tool designed to inspect and manipulate Protected Process Light (PPL) attributes at runtime.

The project provides a clean and modular implementation for interacting with PPL-protected processes through custom IOCTL communication between user mode and kernel mode.

## Overview

PPLReaper enables controlled interaction with the PPL protection level of running processes by exposing three core IOCTL operations:

- **Query PPL status:** Determine whether a target process is running as Protected Process Light.

- **Remove PPL**: Strip PPL protection from a specified process.

- **Add PPL**: Apply PPL protection to a specified process.

The architecture separates responsibilities cleanly:

- Kernel Driver (Ring 0)
Implements the core logic and exposes IOCTL handlers.

- Userland Client (Ring 3)
Communicates with the driver to issue commands and manage targets.

## Features

- Direct kernel-level PPL inspection

- Runtime PPL removal

- Runtime PPL assignment

- Minimal and focused IOCTL interface

## Usage
The userland client (PPLUManipulator.exe) communicates with the kernel driver via DeviceIoControl.

```
PPLUManipulator.exe <PID> <command>
```

#### Commands
- **get:** Show current PPL protection status of the target process
- **protect:** Set process as Protected Process Light (Antimalware signer)
- **unprotect:** Remove PPL protection from the target process

#### Examples
```
PPLUManipulator.exe 1234 get
PPLUManipulator.exe 5678 protect
PPLUManipulator.exe 5678 unprotect
```


## Disclaimer

This project is intended for educational, research, and authorized security testing purposes only.
Misuse of this software may violate local laws and system integrity policies.

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/273861c5-d59e-4058-b56e-a8d1113fb5e3" />
