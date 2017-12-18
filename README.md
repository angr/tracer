# Tracer

This package is in a bit of a complicated transition phase - it originally housed the concolic tracing helpers for angr, but those pieces of code have since been merged into angr proper.
Now, there are still deprecated compatibility layers for this functionality, but the real purpose of this repository should be a set of tools to provide a consistent API for various dynamic trace backends.

The only one currently available is based on qemu-user - `tracer.QEMURunner`.
It relies on some special builds of qemu we've hacked to actually output these traces without the normal problems you sometimes see from qemu's traces with respect to basic block consolidation and optimization.

# Installation
If you have QEMU compilation problems, installing these packages may be useful (tested on Ubuntu 14.04 64bit):

    apt-get build-dep qemu-system
    apt-get install libacl1-dev


