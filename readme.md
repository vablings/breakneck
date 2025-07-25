# breakneck

Simple proof of concept of runtime page encryption from byfron. 
VEH is used to decrypt pages on fault to resume execution, although pages can easily be decrypted by calling the decrypt function or you can just listen to see if the page has been correctly disassembled and caching it.

### todo
- Ensure pages are carefully controlled to avoid encrypting a half instruction 
- Migrate from a loaded DLL to possibly a crate