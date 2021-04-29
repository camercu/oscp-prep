# Bootstrapping Kali Build

These files are intended to bootstrap a fresh Kali build to be ready for hacking
with all of my preferred tools.

## Steps

1. Run `bootstrap.sh` to bootstrap ansible onto Kali.
2. Run `ansible-playbook hackbox-init.yml` to set up Kali with desired tools.