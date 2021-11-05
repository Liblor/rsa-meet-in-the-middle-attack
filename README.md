# Textbook RSA meet-in-the-middle Attack

D. Boneh, A. Joux, and Q. Nguyen showed that textbook RSA is
susceptible to meet-in-the-middle attacks.
Given
<img src="https://render.githubusercontent.com/render/math?math=c = m^e \mod n">
, the following conditions must hold for the attack to be feasible:

- <img src="https://render.githubusercontent.com/render/math?math=m < 2^L">
- <img src="https://render.githubusercontent.com/render/math?math=m_1, m_2 < 2^{L/2}">, s.t. <img src="https://render.githubusercontent.com/render/math?math=m = m_1m_2">

[rsa-meet-in-middle.c](./rsa-meet-in-middle.c) and
[rsa-meet-in-middle-parallelized.c](./rsa-meet-in-middle-parallelized.c)
are sample implementations in C and depend on [GMP](https://gmplib.org).

> [1] Boneh, Dan, Antoine Joux, and Phong Q. Nguyen. "Why textbook ElGamal and
> RSA encryption are insecure." International Conference on the Theory and
> Application of Cryptology and Information Security. Springer, Berlin,
> Heidelberg, 2000. https://doi.org/10.1007/3-540-44448-3_3
