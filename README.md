<h1 align="center">Coercion Resistant Elections</h1>

This library is a basic implementation of coercion resistance elections based on [1] and [2]

#Entities
There are four entities in the CR-election systems:
1. Supervisor: setting the global parameters: number of voters,number of candidates, encrypted list of the candidates, nonce, etc. 
2. Registrars: generate the credentials the voters need to cast their votes
3. Voters
4. Tabulation Tellers (TT)- tally the votes

All agents use a bulletin board (e.g., blockchain)

# The flow of the system
1. Supervisor creates params
2. Tellers engage in a distributed key generation protocol (currently ElGamal) to construct a global public key (called ktt) and each registrar hold a share of a private key
3. Each Registrar creates credential for each voter. Each registrar generates private credential s_i and then encrypt it with the share public key, i.e., compute 
    1. S'_i= Enc(s_i,KTT;r) (where r is a random nonce) and re-encrypt S_i = reenc(S_i,ktt) Post S_i on the bulletin board. 
    2. Post S_i on the blockchain
      3. Send a DVRP proof to the voter proving that S_i is a reenc of S'_i. In particular, it sends (si, r, S'_i, proof) to the voter
4. (Phase 1 - construction of the private share) Each votes receives the private credentials from all the registrars shares from the registrars. Then
   The voter verifies that S'_i was  correctly computed from si and r, then verifies the DVRP (that is, the voter verifies that s_i is indeed a valid private credential share that correspond to the public credential share S_i using DVRP proof (called CredentialShareOutput))
       The voter combine the shares to obtain their private credential. \\
   (Phase 2 - voting) The voter does the following:
   1. encrypt the vote (with ktt) and publish it
   2. send a proof that the vote is in the encrypted list.
   3. encrypt the private credential (with ktt) and publish it   
     4. send a proof of knowledge of vote and the private credential
   
5. Tellers:
      1. For each vote the tellers check the proofs publishes by the voter (4.2 and 4.4)
     2. Mix the votes, and the credentials
     3. Each teller decrypts the vote using their private share (with revealing their share, nor combining their share into a private key)
     3. Tellers tally the votes and publish the results
