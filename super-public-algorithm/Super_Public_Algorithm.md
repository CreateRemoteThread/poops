I found an old board which runs an ECC algorithm -probably a signature.


Every time I run this algorithm, the board uses a new unknown scalar. 


My colleague was able to write a script that recovers the scalar from one power consumption curve. I was able to retrieve one such curve and scalar where he did his magic. Sadly however, we lost the script in the scary depths of our directories...


I captured a power consumption curve. Can you help me retrieve the scalar?


Once you have this scalar, use the ```decrypt_flag.py``` to recover the flag.

