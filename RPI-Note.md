### Raspberry Pis

Yes, Quarterback does work on a Raspberry Pi. Yes, it will even work on a Raspberry Pi 3B!

I would not recommend trying to compile it *on* the Raspberry Pi 3B!
You can, but...

```
    Finished release [optimized] target(s) in 35m 28s
```

Yeah, it takes a *while* to compile on the 3B. It compiles much faster on the 4 (around 8 minutes).

If you want to compile it yourself, I'd highly recommend that you use [cross](https://crates.io/crates/cross)

```
cross build --target aarch64-unknown-linux-musl -r
```

Compiles in about 2 minutes on a "Nanode" from Linode. Or less than 60 seconds on my Ryzen 5 2600 desktop. 

The resulting binary can then be copied to a Raspberry Pi, and it works. 

The aarch64-unknown-linux-musl binaries on this repository are built using cross, with the same command above.
