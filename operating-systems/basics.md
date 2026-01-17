# Operating Systems Basics

## What is an Operating System?
An operating system (OS) is the software layer responsible for managing
hardware resources and providing services to applications.

It acts as an intermediary between:
- hardware (CPU, memory, storage)
- software (applications and services)

Without an OS, applications would need to manage hardware directly.

---

## Program vs Process
A **program** is a static file stored on disk, containing instructions
written in a programming language.

A **process** is an instance of a program in execution.
When a program runs, the operating system creates one or more processes
to manage CPU time, memory usage, and execution state.

Multiple processes can originate from the same program.

---

## System Boot Process (High-Level)
The boot process describes what happens from power-on until the system
is ready for use.

At a high level:
1. Firmware (BIOS/UEFI) initializes hardware
2. A bootloader locates and loads the OS kernel
3. The kernel initializes core system components
4. System services start
5. The user interface becomes available

---

## Resource Management (Concept)
The operating system is responsible for:
- Scheduling CPU time among processes
- Managing memory allocation
- Controlling access to storage and devices

These responsibilities allow multiple applications to run
simultaneously and safely.
