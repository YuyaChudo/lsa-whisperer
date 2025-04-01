This is a collection of header files for working with LSA internals that is maintained for the LSA Whisperer project.
This is the is the most up-to-date set of definitions for working with LSA internals that I know of.

These definitions are gathered from official Microsoft SDKs, symbol files, and manual audits of Windows system files.
The majority of these definitions are undocumented and may be changed by Microsoft at any time.

## Usage

First make sure that your program is using the latest Windows SDK.

These header files are designed to be used by user-mode programs. Instead of including `NTSecAPI.h` or `NTSecPKG.h`, place

```
#include <lwdk.h>
```

at the top of your program.
That line includes definitions for both the main publicly documented APIs for working with LSA and many undocumented internal definitions.
The development kit also comes with `lazy.h`, which may be included to access a set of utility macros for lazy loading APIs.

## Open Source

Thank you to the following packages that are used in the LSA Whisperer Development Kit:

- [winsiderss/phnt](https://github.com/winsiderss/phnt) (license - [MIT](https://github.com/winsiderss/phnt/blob/master/LICENSE))