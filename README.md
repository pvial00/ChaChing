# ChaChing Stream Cipher

Experimental 256 bit stream cipher based loosely on the Salsa/ChaCha round function.  This implementation of ChaChing takes a 256 bit key and a 128 bit nonce and creates a 256 bit state of 8, 32 bit words.  The state is hashed once per round and the resulting 8 word array is processed through the output function (meaning you must know the entire 256 bit array to decrypt a single 32 bit segment.
