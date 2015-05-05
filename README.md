# VulChat
This is a chat server with different vulnerabilities

The idea with this project is insert different vulnerabilities over windows platform to exploit them.

### Vulnerabilities
 * Stack Buffer Overflow

 
### Using Visual Studio. 2013
 * VulChat properties (disable all security properties)
 
  [C/C++ -> Code generation] -> Disable Security Check (/GS-)

  [Linker -> Advanced] -> (/DYNAMICBASE:NO), (/FIXED:NO), (/NXCOMPAT:NO) 
