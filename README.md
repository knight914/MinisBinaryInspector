# MinisBinaryInspector

Read-only Mach-O metadata viewer for OpenMinis (`com.openminis.app`), exactly
version `1.15`, build `16`, on iOS 16 or newer. Existing rootless and roothide
packaging is unchanged apart from the iOS floor. The loader filter matches the
bundle ID; the runtime guard checks OS, marketing version and build before
registering any UI. Other releases, including `1.15.0`, are not supported.

Local source check: `python3 tests/check_target.py`. The portable Mach-O parser
regression can run separately from the iOS tweak:

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 MachO.c tests/parser.c -o /tmp/mbi-parser-tests
/tmp/mbi-parser-tests
```
