
## Finding decryption attacks in ABE schemes

In this section we show, step by step, how to find decryption attacks in 
ABE schemes. First, we start by describing the JSON input file that
ACABELLA expects for looking for this type of attack.

### The JSON input for ACABELLA

In decryption attacks, the MPK value introduces the encodings in the matrix. When using  the AA extended corruption model, this value is equivalent to MPK_AAj. However the MPK_AAj input field is only use for adding descriptive information about the structure of an attribute authority. 

**Note**
> Take into account that both MPK_AAj and MPK_AAi do not insert any additional encoding into the matrix.

### Type of corruptable variables in decryption attacks

Similarly, in decryption attacks the corrupted variables (`DecryptionKeyCorruptedVariable`) can be categorized as:

- MPK_AAi: The variable belongs to an Attribute Authority j. It will be used to obtain the master key of an AA[i].
- misc = misc. variable part of an attribute autority [i].

### Attacking CM14

The CM14 scheme [@cm14] is a multi-authority ABE where there are only distributed AAs and no CA.
During Setup, every authority generates a secret key consisting of \(\alpha_i\), \(\beta_i\) and for every attribte \(j\), \(t_j\).
The public key of every authority consists of the tuple \(e(g, g)^{\alpha_i}\), \(g^{\beta_i}\) and \(g^{t_j}\). Every user
of the system has an identifier (GID). This identifier is involved in the key components to link them to the user.

During key generation, the attribute-independent component is:

- \(D_o\) = \(H(GID)^{1/\beta_i} \cdot g^{\frac{\alpha_i}{\beta_i}}\)

During encryption, the attribute-independent component is \(\beta_i \cdot s\).

#### Obtaining the involved encodings

To obtain the involved key encodings, we take \(D_o\) and replace the hash of GID by
\(g^r\) and add the encoding \(g^r\). Then, we rename \(\beta_i\) as \(\beta_i\) and obtain: 
\((\frac{r + \alpha_i}{b_i}, r)\) as encodings. From the ciphertext encodings, we obtain
\((b_i \cdot s)\). And as MPK encodings, we obtain \(b_i\).

As unknown variables, we have: \(\alpha_i\), \(r\), \(s\), \(b_i\).

#### Generating inputs for ACABELLA

In this case, we can only perform an decryption attack with or without corruption. If we use corruption, we should use the `AA_extended` corruption model, based on the corruption of an attribute authority where we obtain one of its values (and possibly, key or ciphertext components) and on the use of the recovered parameters to attack an honest attribute authority.

Given on the encodings that we have obtained in the past section, we can prepare the following input to ACABELLA for a decryption attack without corruption:

```
{
    "scheme_id": "cm14",
    "analysis": "decryption",
    "k": ["(alpha_i + r) / b", "r"],
    "c": ["s * b"],
    "mpk": ["b"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b"],
    "corruption_model": "NoCorruption",
    "corruptable_vars": [],
    "MPK_AAi": [],
    "MPK_AAj": ["b"],
    "misc_vars": []
}
```

In this case, the output of ACABELLA is: 

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

         k0 : (alpha_i + r)/b
         k1 : r
         c0 : b*s
         mpk0 : b

Structure of CA/AAs:

[!] No decryption attack found
```

We can also try the AA_extended corruption model. We'll suppose we obtain the \(b_i\) parameter of a corrupted authority \(AA_i\), \(b_2\). Then, we'll obtain ciphertext encodings from that authority too. The goal is to attack, using those encodings, a honest authority \(AA_j\). We prepare the following input for ACABELLA:

```
{
    "scheme_id": "cm14",
    "analysis": "decryption",
    "k": ["(alpha_i + r) / b", "r"],
    "c": ["s * b", "s * b2"],
    "mpk": ["b"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b"],
    "corruption_model": "AA_extended",
    "corruptable_vars": [
        { "type":"MPK_AAi", "var":"b2" }
         ],
    "MPK_AAi": ["b2"],
    "MPK_AAj": ["b"],
    "misc_vars": []
}
```

ACABELLA finds the following attack:

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k0[i]*c0 : s*(alpha_i + r)
         k1[i]*c1 : b2*r*s
         k1[i]*mpk1 : b2*r
         c0*mpk1 : b*b2*s
         c1*mpk0 : b*b2*s
         k[i]0 : (alpha_i + r)/b
         k[i]1 : r
         c0 : b*s
         c1 : b2*s
         mpk0 : b
         mpk1 : b2

For the corruption of an attribute authority AA[i] where c0 and c1 are obtained from different attribute authorities.

Structure of CA/AAs:
        Master key pair of AA[i]: mpk[i]: [b2]
        Master key pair of AA[j]: mpk[j]: [b]

List of variables obtained via corruption:
        b2 from MPK_AAi

[*] Decryption attack found: 1*k0[i]*c0 + -1/b2*k1[i]*c1
```

### Attacking PO17

The PO17 scheme [@po17] is a MA-ABE scheme with a similar structure as CM14.
It only consists of multiple attribute-authorities AA in a distributed
fashion. 

- During `Setup`, every attribute authority generates \(\alpha_i\), \(\beta_i\) and \(t_{i_k}\) (for every supported attribute \(k \in_R Z_p\) as the master secret key tuple MSK. The MPK of every authority consist then on \(X_i = g^{\beta_i}\) and \(Y_i = e(g, g)^{\alpha_i}\).  Moreover, for every attribute \(k\), an associated public key is generated as
\(T_{i, k} = g^{t_{i, k}}\). 

- The key generation component that is attribute-independent is \(SK_o^k = g^{\frac{\alpha_i - r_i}{\beta_i}}\).

- In the encryption process, the attribute-independent variables correspond to \(g^{\beta_i \cdot s}\). 

#### Obtaining the involved encodings

We rename the key generation component \(SK_o^k\) as \(\frac{\alpha_i - r}{b_i}\) and we 
add the corresponding encoding of \(g^r\), \(r\). From the ciphertext component, we rename it as \(b_i \cdot s\). Finally, we also add the MPK corresponding to the attribute authority to the encoding list.

#### Generating inputs for ACABELLA

We follow the same strategy as with the CM14 [@cm14] scheme, using the `AA_extended` corruption model. We create the following JSON input:

```
{
    "scheme_id": "po17",
    "analysis": "decryption",
    "k": ["(alpha_i - r) / b", "r"],
    "c": ["s * b", "s * b2"],
    "mpk": ["b"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b"],
    "corruption_model": "AA_extended",
    "corruptable_vars": [
        { "type":"MPK_AAi", "var":"b2" }
         ],
    "MPK_AAi": ["b2"],
    "MPK_AAj": ["b"],
    "misc_vars": []
}
```

and ACABELLA finds the following decryption attack:

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k0[i]*c0 : s*(alpha_i - r)
         k1[i]*c0 : b*r*s
         k0[i]*mpk0 : alpha_i - r
         k0[i]*mpk0 : alpha_i - r
         k1[i]*mpk0 : b*r
         k1[i]*mpk0 : b*r
         c0*mpk0 : b**2*s
         c0*mpk0 : b**2*s
         k[i]0 : (alpha_i - r)/b
         k[i]1 : r
         c0 : b*s
         mpk0 : b
         mpk0 : b

For the corruption of an attribute authority AA[i].

Structure of CA/AAs:
        Master key pair of AA[i]: mpk[i]: [b]

List of variables obtained via corruption:
        b from MPK_AAi

[*] Decryption attack found: 1*k0[i]*c0 + 1/b*k1[i]*c0
```

### Attacking NDCW15

The NDCW15 scheme [@ndcw15] is a CP-ABE scheme with traceability capabilities to detect illegal key redistribution. 

During `Setup`, the master key of the system, \(alpha_i\) is generated as well  as the corresponding public keys of every attribute in the system and the rest of public parameters (\(g^k\) for instance is relevant to us as it appears in one of the attribute-independent ciphertext components).

We are interested in the following key components, that are attribute-independent:

- \(K = g^{\frac{\alpha}{a + T}} \cdot (g^t)^{\frac{r}{a + T}}\)

for \(r \in_R Z_p^{*}\) and \(c \in_R Z_N\).

- \(L = g^c \cdot R_o\)

- \(L_p = g^{a\cdot c} \cdot Rp_o\)

where \(c\) is known by the user as well as \(T\).

From `Encryption`, we are interested in the following ciphertext encodings:

- \(C_0 = g^s\)
- \(C_1 = g^{a\cdot s}\)
- \(C_2 = g^{k \cdot s}\)

The user knows the following variables \(c\) (sent by the authority), \(t\) (generated by the user) and \(T\), that is part of one attribute-independent component of the key.

#### Obtaining the involved encodings

We rename the known variables by the user as \(x_i\) variables:

- \(c\) becomes \(x_1\)
- \(t\) becomes \(x_2\)
- \(T\) becomes \(T\)

The global parameters are renamed as:

- \(a\) becomes \(b_1\)
- \(k\) becomes \(b_2\)

Now, the corresponding key encodings are:

- \(\frac{\alpha + x_2 \cdot b_2}{b_1 + x_3}\)
- \(b_1 \cdot x_1\)

And the corresponding ciphertext encodings are:

- \(s\)
- \(b_1 \cdot s\)
- \(b_2 \cdot s\)

#### Generating inputs for ACABELLA

If we try a decryption attack without corruptin with the following input:

```
{
    "scheme_id": "ndcw15",
    "analysis": "decryption",
    "k": ["alpha * (1 / (b1 + x3)) + x2 * b2 * (1 / (b1 + x3))", "x1", "x1 * b1"],
    "c": ["s", "s * b1", "s * b2"],
    "mpk": [],
    "gp": ["b1", "b2", "1"],
    "key" : "alpha * s",
    "unknown_vars" :  ["alpha", "b1", "b2", "s"],
    "corruption_model": "NoCorruption",
    "corruptable_vars": [],
    "MPK_AAi": [],
    "MPK_AAj": [],
    "misc_vars": []
}
```

ACABELLA finds a decryption attack:

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k0*c0 : s*(alpha/(b1 + x3) + b2*x2/(b1 + x3))
         k0*c1 : b1*s*(alpha/(b1 + x3) + b2*x2/(b1 + x3))
         k1*c0 : s*x1
         k1*c1 : b1*s*x1
         k1*c2 : b2*s*x1
         k2*c0 : b1*s*x1
         k2*c1 : b1**2*s*x1
         k2*c2 : b1*b2*s*x1
         c0*gp0 : b1*s
         c0*gp1 : b2*s
         c0*gp2 : s
         c1*gp0 : b1**2*s
         c1*gp1 : b1*b2*s
         c1*gp2 : b1*s
         c2*gp0 : b1*b2*s
         c2*gp2 : b2*s
         k1*gp0 : b1*x1
         k1*gp1 : b2*x1
         k2*gp2 : b1*x1
         k0 : alpha/(b1 + x3) + b2*x2/(b1 + x3)
         k1 : x1
         k2 : b1*x1
         c0 : s
         c1 : b1*s
         c2 : b2*s
         gp0 : b1
         gp1 : b2
         gp2 : 1

[*] Decryption attack found: k0*c0*x3 + 1*k0*c1 + -x2/x1*k1*c2
```

### Attacking YJ14

The YJ14 scheme [@yj14] is a MA-ABE scheme that uses one central authority and several attribute authorities. The CA runs the Setup algorithm and registers users and AAs. The AAs are independents and generate attribute public and secret keys as well as revoke attributes. The scheme is cloud-centered and also consists of a cloud server, data owners (those who encrypt and store ciphertextexts in the cloud) as well as data consumers (or users, those who decrypt ciphertexts if they can fulfill an access policy).

During Setup, the CA generates  global master key comprised of \(a\), \(b \in_R Z_p\). It also publishes the global system parameters tuple, consisting of \(g\), \(g^a\), \(g^b\) and the hash function \(H\). During the user registration functionality, the CA generates \(u_{uid}\) and \(up_{uid} \in_R Z_p\) and generates the following keys:

- \(GSK_{uid} = u_{uid}\)
- \(GSKp_{uid} = up_{uid}\)
- \(GPK_{uid} = g^{u_{uid}}\)
- \(GPKp_{uid} = g^{up_{uid}}\)

It sends to the user \(GPK_{uid}\), \(GSKp_{uid}\) and a certificate.

It also generates an identifier, aid to every AA involved in the system.

Each \(AA_i\) generates the parameters: \(\alpha_i\), \(\beta_i\) and \(\gamma_i \in_R Z_p\).
The AA public key consists of \(e(g, g)^{\alpha_i}\), \(g^{\beta_i}\) and \(g^{\frac{1}{\beta_i}}\).

We are interested in the following key encodings, which are attribute-independent:

- \(K_0 = g^{\alpha_i} \cdot g^{a \cdot u_{uid}} \cdot g^{b \cdot t_{uid}}\)
- \(K_1 = g^{t_{uid}}\)

where \(t_{uid, aid}\) is generated \(\in_R Z_p\).

Finally, we are interested in the following ciphertext encodings (which are attribute-independent):

- \(C_p = g^s\)
- \(C_{pp} = g^{b \cdot s}\)

#### Obtaining the involved encodings

- We identify the \(a\) and \(b\) encodings that are part of the global parameters. We rename \(a\) to \(b\) and \(b\) to \(b_p\).
- The user secret key, \(u_{uid}\) parameter, is renamed it as \(x\). This parameter is kept secret and distributed in the attribute authorities.
- The key encodings are then \(\alpha_i + b\cdot x + b_p\cdot r\) and \(r\).
- The ciphertext encodings are \(s\) and \(b_p\cdot s\).
- The unkown variables in this case are `["alpha_i", "b", "bp", "r", "s", "x"]`.

#### Generating inputs for ACABELLA

Given the identified encodings, we can try to find a decryption attack with the following input:

```json
{
    "scheme_id": "yj14",
    "analysis": "decryption",
    "k": ["alpha_i + x * b + r * bp", "r"],
    "c": ["s", "s * bp"],
    "mpk": ["b", "bp"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "b", "bp", "r", "s", "x"],
    "corruption_model": "NoCorruption",
    "corruptable_vars": [],    
    "MPK_AAi": ["alpha_i", "x"],
    "MPK_AAj": [],
    "misc_vars": ["x"]
}
```

However, ACABELLA doesn't find an attack:

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k1*c1 : bp*r*s
         k0 : alpha_i + b*x + bp*r
         k1 : r
         c0 : s
         c1 : bp*s
         mpk0 : b
         mpk1 : bp

Structure of CA/AAs:

[!] No decryption attack found
```

Every attribute authority in the system contains the user secret key \(u_{uid}\). It could be that having this parameter could enable a decryption attack. In order to check that, we can corrupt an \(AA_i\), obtain \(x\) and then launch an attack against an honest authority \(AA_j\). In this case, we'll use the `AA` corruption model (there is no CA involved), and we'll obtain the variable \(x\) from a corrupted authority:

```json
{
    "scheme_id": "yj14",
    "analysis": "decryption",
    "k": ["alpha_i + x * b + r * bp", "r"],
    "c": ["s", "s * bp"],
    "mpk": ["b", "bp"],
    "gp": [],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "b", "bp", "r", "s", "x"],
    "corruption_model": "AA",
    "corruptable_vars": [
        { "type":"misc", "var":"x" }
         ],    
    "MPK_AAi": ["alpha_i", "x"],
    "MPK_AAj": [],
    "misc_vars": ["x"]
}
```

In this case, ACABELLA shows us how to perform a decryption attack:

```bash
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k0[i]*c0 : s*(alpha_i + b*x + bp*r)
         k1[i]*c1 : bp*r*s
         c0*mpk0 : b*s
         c1*mpk0 : b*bp*s
         k[i]0 : alpha_i + b*x + bp*r
         k[i]1 : r
         c0 : s
         c1 : bp*s
         mpk0 : b
         mpk1 : bp

For the corruption of an attribute authority AA[i].

Structure of CA/AAs:
        Master key pair of AA[i]: mpk[i]: [alpha_i, x]

List of variables obtained via corruption:
        x from AAi

[*] Decryption attack found: 1*k0[i]*c0 + -1*k1[i]*c1 + -x*c0*mpk0
```

### Attacking YJR13

The YJR13 scheme [@yjr13] is a multi-authority scheme that uses a CA and several attribute authorities. The problem of this scheme, as we'll see is that the user knows two exponents that enable it to perform a decryption attack without the need of corruption.

- The CA, during `Setup`, generates \(a \in_R Z_p\) as master key and publshes \(g^a\) as part of the system parameters.
- During the user registration, the CA generates \(GPK_{uid} = g^{u_{uid}}\) and \(GSK_{uid} = z_{uid}\) via \(u_{uid}\) and \(z_{uid} \in_R Z_p\). In this scheme, the user knows \(z_{uid}\) a well as its uid (used as \(u_i\) in the scheme).
- The AAs, during `Setup`, generate \(\alpha_i\), \(\beta_i\) and \(\gamma_i \in_R Z_p\) as secret key and publish as public key: \(e(g, g)^{\alpha_i}\), \(g^{\frac{1}{\beta_i}}\), \(g^{\frac{\gamma_i}{\beta_i}}\).
- During key generation, the followign attribute-independent components are generated: \(K_i = g^{\frac{\alpha_i}{z_j}}\cdot g^{a\cdot u_i}\cdot g^{\frac{a}{\beta_i}\cdot t_i}\), \(L_i = g^{\frac{\beta_i}{z_i}\cdot t_i}\) and \(R_i = g^{a\cdot t_i}\)
for \(t_i \in_R Z_p\).
- We are interested in the following attribute-independent components generated during encryption: \(C_p = g^s\) and \(C_{pp} = g^{\frac{s}{\beta_i}}\).

#### Obtaining the involved encodings

- We know that the user has \(z_i\), that we rename as \(x_1\) and \(u_i\), renamed as \(x_2\).
- The random exponent \(t_i\) is renamed as \(r_i\).
- The key encodings are then: \(\frac{\alpha_i}{x_1} + b\cdot x_2 + \frac{b}{b_i}\cdot r\), \(\frac{b_i}{r}\) and \(b\cdot r\).
- The global parameter \(a\), generated by the CA is also involved in our analysis and we rename it as \(b\).
- The MPK triple of every attribute authority i consists of \(\alpha_i\), \(\beta_i\) (renamed as \(b_i\)) and \(\gamma_i\), renamed as \(b_{pp}\).
- The ciphertex-related encodings are \(s\) and \(\frac{s}{b_i}\).

#### Generating inputs for ACABELLA

Since the user knows already two exponents in the scheme, we can try to find an attack without corruption using the following input:

```json
{
    "scheme_id": "yjr13",
    "analysis": "decryption",
    "k": ["alpha_i * (1 / x1) + x2 * b + r * (b / bp)", "r * bp * (1 / x1)", "r*b"],
    "c": ["s", "s / bp"],
    "mpk": ["bp"],
    "gp": ["b"],
    "key" : "alpha_i * s",
    "unknown_vars" :  ["alpha_i", "r", "s", "b", "bp"],
    "corruption_model": "NoCorruption",
    "corruptable_vars": [],    
    "MPK_AAi": ["alpha_i", "bp"],
    "MPK_AAj": [],
    "misc_vars": ["x1", "x2"]
}
```

ACABELLA finds the following attack:

```
[*] ACABELLA cmd tool


[*] Analyzing scheme...



[*] Decryption key attack results:

List of encodings:
         k0*c0 : s*(alpha_i/x1 + b*x2 + b*r/bp)
         k2*c1 : b*r*s/bp
         k2*mpk0 : b*bp*r
         c0*gp0 : b*s
         c1*gp0 : b*s/bp
         k1*gp0 : b*bp*r/x1
         k0 : alpha_i/x1 + b*x2 + b*r/bp
         k1 : bp*r/x1
         k2 : b*r
         c0 : s
         c1 : s/bp
         mpk0 : bp
         gp0 : b

Structure of CA/AAs:

[*] Decryption attack found: k0*c0*x1 + -x1*k2*c1 + -x1*x2*c0*gp0
```

## Advice on finding decryption attacks

- Sometimes, it is possible to corrupt an attribute authority and obtain a variable, that, together
with an ciphertext component from the same attribute, allow us to attack an honest attribute authority.
See for instance the attack against the CM14 and PO17 schemes.

# References

