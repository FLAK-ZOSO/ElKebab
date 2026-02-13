#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Compile
gcc -o elkebab elkebab.c -lcrypto

PRIV=privatekey.txt
PUB=publickey.txt
RFILE=alice_r.txt
COMMIT=commit_out.txt
BET=12

# Generate keys
./elkebab genkey "$PRIV" "$PUB"

# read hex contents (strip newlines)
PUB_HEX=$(tr -d '\r\n' < "$PUB")
RFILE_HEX_PATH="$RFILE"

# Commit (pass pub hex string, save randomness hex to file and commitment to stdout)
./elkebab commit "$PUB_HEX" "$BET" "$RFILE" > "$COMMIT"

# Extract R and S
R=$(grep '^R=' "$COMMIT" | cut -d'=' -f2- | tr -d '\r\n')
S=$(grep '^S=' "$COMMIT" | cut -d'=' -f2- | tr -d '\r\n')

echo "R = $R"
echo "S = $S"
echo "r (kept secret) saved in $RFILE"

# read r hex (strip newline) for verify
R_HEX=$(tr -d '\r\n' < "$RFILE")

# Verify
echo "Verifying..."
./elkebab verify "$PUB_HEX" "$R" "$S" "$BET" "$R_HEX"
echo "Done."

# Send R, S, and bet to your friend for verification
echo "Send the following to your friend for verification:"
echo "R: $R"
echo "S: $S"
echo "Public Key: $PUB_HEX"

# Do not share the contents of $RFILE (the randomness) with anyone else!
echo "Keep the contents of $RFILE secret, as it can be used to open the commitment and reveal your bet."
