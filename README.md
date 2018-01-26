# Stream cipher based on hash function and Counter mode encryption (CTR)

Learning example for Counter mode encryption (CTR) and idea for using hash-function as a gamma generator for steam cipher.

Algorithm:
1. Create random Nonce. One Nonce used for every round
2. Create CounterBlock for round 

CounterBlock = Counter XOR Nonce

3. Gamma generator (HMAC here) create RoundGamma for round

Gamma = HMAC(CounterBlock, Key)

4. Create cipherText = PlainText XOR RoundGamma
5. When Gamma is over, began next round. 

Counter = Counter + 1

so new round get new Gamma
