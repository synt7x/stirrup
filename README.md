# Stirrup

Experimental PE file creator targeting Win64. Not recommended for use in production, I made this just to get familiar with the PE file format.

# Running

You need Lua5.1 or greater installed in order to run stirrup. Run using:

```
lua win64.lua [options]
```

# Options

* `-o <file>`: Output file
    * Default: `program.asm`
* `-f <format>`: Format to output to
    * Default: `machine`
    * Options: `machine`, `asm`
* `-a <alignment>`: File alignment
    * Default: `512` (supports any number)


# Examples

```
lua win64.lua -o example.asm -f asm -a 0
```

```
lua win64.lua -o example.exe -f machine -a 1024
```

# More Info

* When compiling to assembly, it only generates the assembly to return 0.
* When compiling to machine code, it generates an exe that prints "Hello PE world!"
* This project will never recieve updates, though the information used for this may be applied to [LuaNext](https://github.com/LuaNext)