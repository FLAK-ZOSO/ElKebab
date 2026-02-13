# ElKebab - How cryptography enables gambling

Suppose you want to bet a kebab with a friend on how many people will fail the algorithms and data structures exam, but you are both part of the course and thus in the position to alter the bet in your own interest in various undesirable ways.

Then the best way to do this is a cryptographic commitment scheme such as the ElGamal or Pedersen commitment schemes. This comes implemented in a purely vibecoded and likely highly vulnerable piece of software called **ElKebab**: it's your lucky day.

## Usage

### Compile

The code is written in C and can be compiled with `gcc`:

```bash
gcc -o elkebab elkebab.c -lcrypto
```

### Create your own keypair

```bash
./elkebab keygen privatekey.txt publickey.txt
```
*The format of the keys is not specified, but it is compatible with other operations with the same software.*

### Commit to a bet

Now you will want to commit to a bet to your friend. You can do this with the `commit` command:

```bash
# it's safer to pass filenames or ensure the public key is a single-line string
./elkebab commit publickey.txt 12 r.txt > commitment.txt
```

This will create a commitment to the bet `12` with a random value `r` stored in `r.txt`, and the commitment itself will be stored in `commitment.txt`.

### Verify the commitment

When the exams session is over, you can send the following to your friend so they can verify that it is a valid commitment to the given bet using their public key and this same software.

- The bet `12`
- The random value `r` stored in `r.txt`

The following command will verify the commitment:

```bash
# R and S are the commitment components (from commitment.txt); r is the random opening (from r.txt)
./elkebab verify publickey.txt <R> <S> 12 <r>
```
*Where `R` and `S` are the components of the commitment stored in `commitment.txt`.*
