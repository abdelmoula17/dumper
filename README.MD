# MEM DUMPER

This small Rust program is inspired by this article ["recover lost text by coredumping firefox"](https://j3s.sh/thought/recover-lost-text-by-coredumping-firefox.html), The article discusses the frustration of losing text due to browser glitches, crashes, or poorly designed websites. The author shares a trick to recover lost text by coredumping Firefox and searching for the lost text in the core dump.

## Usage

1. Clone the repository:

   ```
    git clone https://github.com/abdelmoula17/dumper.git
   ```

2. Build the program:

   ```
    cd mem_dump
    cargo build --release
   ```

3. Run the program:

   ```
    ./target/release/mem_dump <pid>
   ```

   A `pid-dumper.dp` file will be generated, this file contains all the garbage on the stack/heap memory of the process.

   To search for lost text in the pid-dumper.dp file:

   ```
   cat pid-dumper | grep "lost text"
   ```
