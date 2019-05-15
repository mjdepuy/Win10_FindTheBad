# Win10_FindTheBad
PowerShell script to find bad things on a Windows 10 machine.

READ: THIS HAS ONLY BEEN TESTED ON WINDOWS 10!

# How it works
Simply run "win10_find_bad.ps1", either as admin (full fidelity) or user (partial fidelity). Output is sent to STDOUT, so you may redirect it to a file if you choose to.

# Included in the report
Device info (Username, computer name, network configuration, current network connections)

Processes list

Services list

Loaded modules list

Recycle bin analysis (all metadata from $I files)

Registry info (Run/RunOnce keys, userinit, process MRU, RunMRU, RecentDocs for current user)

LNK File listing

Prefetch file listing (admin required)


# TODO List
Dump everything to individual files

Prefetch parsing

LNK file parsing

Chrome/FireFox extensions (listing/parsing)

IE/Edge/Crhome/FireFox history

Certificates
