# xxh3-port

This is a pretty straightforward port of the [XXH3 C implementation][XXH3C] to Rust, with a focus on keeping the streaming version of as fast as possible for the case where many small updates to the state are being done. As it is a straight port of C code it does not look like idomatic Rust in some places.

[XXH3C]: https://github.com/Cyan4973/xxHash
