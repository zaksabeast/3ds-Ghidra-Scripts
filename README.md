# 3ds Ghidra Scripts

These are ghidra scripts to help with 3ds reverse engineering.

Features:

- Labels, comments (when inlined), and bookmarks svc use
- Labels service handles, given ctr::srv::GetServiceHandleDirect
- Labels IPC functions and uses handles to better identify functions
- Adds `ThreadLocalStorage` and types thread local storage
- Renames thread local storage to 'tls'

These have been built over time for my personal use as needs came up, so results may vary and improvements can be made. If you run into a situation where these don't work as intended, I would happily accept a PR.

## Credits

Thanks to:

- [3dbrew](https://www.3dbrew.org/wiki/Services_API) for almost everything in the services.py file
- HackOvert for [their ghidra snippets](https://github.com/HackOvert/GhidraSnippets)
