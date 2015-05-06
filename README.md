# VulChat
This is a x64 chat server with different vulnerabilities

The idea with this project is insert different vulnerabilities over windows platform to exploit them.

### Vulnerabilities
 * Stack Buffer Overflow

 
### Using Visual Studio. 2013

 * First  disable all security properties

  [C/C++ -> Code generation] -

  Disable Buffer Overrun Detection (/GS-)

  [Linker -> Advanced]
  
  Disable ASLR         (/DYNAMICBASE:NO)
  
  Disable Relocations  (/FIXED:NO)
  
  Disable DEP          (/NXCOMPAT:NO) 
  
  Exception Handling Protection (/SafeSEH:NO) Dont for x64

  Structured Exception Handler Overwrite Protection (SEHOP) disable in the register

 * Second to compile the project you have to add the _CRT_SECURE_NO_WARNINGS definition to your project's settings
