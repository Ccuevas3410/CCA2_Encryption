# CCA2 Encryption:

> Build a public key cryptosystem using a key encapsulation mechanism (KEM)

## Background
- For:
    - CSC480 Computer Security Project1
- Idea:
    - build asymmetric system
        - RSA
            - using GMP to operate with arbitrary precision numbers 
    - build symmetric system denoted as SKE
        - SKE that works only on buffers
        - SKE that works on files
        - SKE
            - Encryption:
                - 16 byte IV | C = AES(plaintext) | 32byte SHA256 HMAC(C)
                - IV = initialization vectors, unpredictable random number to make sure that when same message is encrypted more than once, the ciphertext is different 
            - Decryption:
                1. Check hmac of iv + c
                2. Decrypt ciphertext 
    - KEM:
        - combine RSA and SKE on files
        - ciphertext will be:
            - RSA-KEM(x) | SKE ciphertext
            - Generate SKE key with x, where x has a much 

## Overview
-  

## How to Run
1. make
    - run the make file
2. ./kem-enc -h

## Notes
- This was tested on an UbuntuLinux environment.
                
## Member Notes for Git
### To Push Changes
1. Push the changes to own branch
	- `git add <file>`
	- `git commit -a -m <message>`
	- `git push`
2. Merge and push from master branch to master remote
	- `git checkout master`
	- `git merge <user branch>`
	- `git push`
3. Go back to own branch
	- `git checkout <user branch>`

### To Fetch Changes
1. Make sure local branch is updated
	- `git add <files>`
	- `git commit -a -m "message"`
	- `git push`
2. Pull from Master branch
	- `git checkout master`
	- `git pull`
3. Merge with Master from own branch and push
	- `git checkout <user branch>`
	- `git merge master`
	- `git push`

## Members
- [Justin F. Chin](https://github.com/justinfchin)
- [Victor Hong](https://github.com/vhong000)
- [Sunny Mei](https://github.com/Sunny3oy)
- [Carlos Ng](https://github.com/Cng000)
