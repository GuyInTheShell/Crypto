# Modulus reuse

## Known information

* `M` a message
* `N` = pq the modulus
* `e1` a public exponent
* `C1 = M**e1 mod N` a cyphertext of M
* `e2` a public exponent
* `C2 = M**e2 mod N` a cyphertext of M

## Attack

If `GCD(e1, e2) = 1` (which is generally the case), the we can find `s1`, `s2` such that
`e1s1 + e2s2 = 1`.

Then
```
  C1**s1 . C2**s2 = M**(e1.s1) . M**(e2.s2) mod N
                  = M**(e1.s1 + e2.s2) mod N
                  = M mod N
```

## Information retrieved

We were able to recover a plaintext message that was encrypted twice with the same modulus.

However, we still do not know `p` and `q` and have therefore not broken this generic communication.

## Example

_(Needs python 3.8+)_

# Inputs

N: The modulus
c1: The first cyphertext of M
e1: The public exponent of the first cyphertext of M
c2: The second cyphertext of M
e2: The public exponent of the second cyphertext of M

# Attack algorithm

```python3
def find_M_from_reused_modulus(N, e1, e2, c1, c2):
  s1 = pow(e1, -1, e2)
  # s1 = 8
  s2 = int((1 - e1*s1) / e2)
  # s2 = -3

  # We need to work with positive exponents only

  if s1 < 0:
    D = pow(c1, -1, N)
    M = pow(D,-s1,N) * pow(c2,s2,N) % N
  else:
    D = pow(c2, -1, N)
    M = pow(c1,s1,N) * pow(D,-s2,N) % N

  return M
```

# Test

## Small values

```python3
N = 10403       # Note that a real N would be much bigger, but here it does not matter
e1 = 5
e2 = 13
c1 = 6582
c2 = 2445

find_M_from_reused_modulus(N, e1, e2, c1, c2)
```

## Real values

We'll use a 2048 bits long private key

```python3
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

private_key.private_numbers().__dict__

# In my case
#
# p: 169629860424840406060454041625511884986727675018997699255841431725290258274656560187552022332535434954942538291249103836826297724022098897454324639612217531356668933257839243443451540066617183873016881552690502348380905446813302071301014949694134998199174779743043259868533262759074315816391174778328316789023,
# q: 152608315733614172271154129936657300671381446929343697710342128802933606166776256955038003518935513656588465534594230825904225012771801210706038254899184777048253551703760067697229624111811851460877112404931630893797011437564717603943545838499837612699522542271640703736251602542978469697996892494794506553103,
# e: 65537
# n: 25886927297562948160842379366367220919574689236650192796026896450823034834218029360547981911421067108515959827112959128686464989288869086290222663479921368632289387357504149270930016390304780213593400516425112305615658845937592637043211266318066449116733371212013671484025257132208847773457655634217191828624104643265070520966986003262298068761902314962454859975876303377680343911759713161267474877493494162093772815167194418894961400508756270924055760015142712977007678810139439462882819646462831409164037897778095980247012741576730124901866795206008458425058850205907798676012589290197948312500671369868508596988369

# We'll use
p = private_key.private_numbers().p
q = private_key.private_numbers().q
e1 = private_key.public_key().public_numbers().e
n = private_key.public_key().public_numbers().n
e2 = 13
M = "The quick brown fox".encode()
M_num = int(M.hex(), 16)

# We get
c1 = pow(M_num,e1,n)
c2 = pow(M_num,e2,n)

M_decrypt = find_M_from_reused_modulus(n, e1, e2, c1, c2)

binascii.unhexlify(hex(M_decrypt)[2:])
```


[See here](https://math.stackexchange.com/questions/2730675/decrypt-an-rsa-message-when-its-encrypted-by-same-modulus)
