
# Introduction

Attribute-based encryption is a type of public key encryption in which the keys are linked
to attributes. It enforces access control on a cryptographic level in a fine-grained
fashion. For instance, a person with attributes Department = Research `and` Auditor = Yes could
satisfy an access policy Department = Finance `or` Auditor = Yes. Both ABE and its multi-authority
variant, MA-AE can be used in the Cloud and in medical environments to protect private data. 

`ACABELLA` is a tool for analyzing the security of ABE schemes.
This documentation details the different components of 
`ACABELLA`, how to analyze the security of an ABE scheme and how to look for
master key and decryption attacks. `ACABELLA` is written in Python and uses Sympy as
the main dependency.

There are three ways of using `ACABELLA`:

- Via the `Attack` classes, which independently provide methods for finding master key and
decryption attacks and analyze the security of an ABE scheme.
- Via the `Analysis` class, which prepares batches of attacks and run them on the description
of an ABE scheme.
- Via the `Analysis` class using the JSON `ACABELLA` format, which describes the properties of an ABE scheme and
particular corruption environments where security is analyzed.

and two main tools:

- `acabella_cmd`: A command line tool, based on python, for analyzing the security of ABE schemes based on the `ACABELLA`
JSON format. It provides an easy way to access the different checks and analysis that are implemented
in `ACABELLA`.
- `acabella_web`: A web interface built with Flask that provides a similar functionality as `acabella_cmd`. It comes
with prefilled forms to help the user to understand the different inputs required for analyzing an ABE scheme.

## ABE and MA-ABE schemes

ABE can be implemented using different cryptographic primitives. In this work, we focus
on pairing-based (MA) - ABE. Typically, the parties involved in ABE are:

- Key generation authorities (KGA): They are part of ABE schemes and could appear as Central Authorities
  (CAs) in MA-ABE schemes, together with distributed Attribute Authorities (AAs). A KGA typically
  generates the master key pair MPK, MSK. They generate secet keys associated to sets of attributes using the master key,
  which can be used to decrypt any ciphertext.
- Users, which can be data consumers (e.g. they can fulfill an access policy with their attributes and have access to
sensitive data) or data owners: they encrypt sensitive data using a particular access policy.
- An storage entity such as the Cloud, where ciphertexts are stored and available to data consumers.

Both ABE and MA-ABE schemes have several security requirements. First, master keys should be hidden in secret keys. Second,
a scheme should provide collusion security, that is, users with keys related to attributers shouldn't be able to collude
an access sensitive data protected with an access policy that they cannot fulfill independently. Finally, in MA-ABE we assume
that the scheme includes the notion of corruption in their security model. That means, that an
attacker can corrupt one or more authorities (AAs) in an attack. However, this fact shouldn't give enough power to
attack an honest authority. Similarly, we should take into account that in MA-ABE schemes where CA and AAs are involved,
different corruption cases could apply which could yield attacks if the respective security model is not well defined.

`ACABELLA` automates the verification of different security properties and looks for the existence of attacks in a scheme.
It relies on the following analysis frameworks:

- The Venema-Alpar cryptanalysis framework [@bbs]
- The AC17 framework [@ac17]
- The FAEBO property [@fabeo]

## Pair encodings

The Venema-Alpar framework [@bbs] analyzes the security of a scheme according to its pair encoding. 
The pair encoding shows what happens in the realm of the exponent. Since we are focusing on pairing-based
ABE schemes, keys and ciphertext components exists in two groups: \(\mathbb{G}\) and \(\mathbb{H}\). For a pairing \(e: \mathbb{G} \times \mathbb{H} \implies
\mathbb{G}_T\) with generator \(g \in \mathbb{G}\) and \(h \in \mathbb{H}\), keys and ciphertext components have the following form:

- SK \(= h^{k(\alpha, r, b)}\)
- CT \(= m\cdot e(g, h)^{\alpha \cdot s}\), \(g^{c(s, b)}\)

In this case, \(k\) and \(c\) are the ke and ciphertext encoding of the scheme.
\(\alpha\) is the master key, \(b\) is part of the public key and \(r\), \(s\) are random values
linked to a keys and ciphertext respectively.

More generally, we can see pair encodings as a way of encoding the inputs \(x\), \(y\) of a predicate into polynomials made of 3 type of variables:

  - Common variables, which are shared by the \(x\), \(y\) encodings and that are typically designated in ABE as \(b_1, b_2\), etc.
  - Specific variables for the encoding of \(x\), in ABE typycally designated as \(s_0, s_1, s_2\), etc.
  - Specific variables for the encding of \(y\), in ABE typically designated as \(\alpha, r_1, r_2\), etc.

The input \(x\) is related to the ciphertext part and the input \(y\) to the key. 

The common variables \(b_1, b_2\), etc. generally appear as \(g^{b_1}, g^{b_2}\), etc. in the system parameters of the scheme and are generated \(\in_R Z_p\). Further, \(\alpha\) appears as part of \(e(g, h)^{\alpha}\), which is the MSK of the system and is generated \(\in_R Z_p\). 

Encrypting a message using attributes x means generating random numbers \(s_1, s_2\), etc. in order to create new terms common or not common with \(b_i\) variables. Then, the message is integrated into the ciphertext with a blinding factor, via the re-randomization of \(e(g, h)^{\alpha}\) as \(e(g, h)^{\alpha \cdot s}\). 

Finally, the exponents in key components consist of variables \(r_1, r_2\), etc. \(\in_R Z_p, b_i\) variables and possibly \(\alpha\). For \(P(x, y) = 1\) it is possible to combine ciphertext and key encodings in order to retrieve \(\alpha \cdot s\) and consequently the message.

## The Venema-Alpar cryptanalysis framework

The Venema-Alpar cryptanalysis framework [@bbs] extends the pair encodings to MA-ABE schemes and
provides a categorization of different possible attacks and different heuristics to 
find them. It employs linear approach to the security analysis of ABE schemes. It looks
for cases where the master key can be recovered and analyzes in which cases users can collude and
decrypt ciphertexts. Finally, it models the notion of corruption for MA-ABE schemes.

The security of a scheme depends on the possibility of obtaining \(e(g, h)^{\alpha \cdot s}\) using ciphertext
components an a non-authorized secret key. This would mean to obtain \(\alpha \cdot s\)
via a linear combination of \(k(\alpha, r, b)\) and \(c(s, b)\). This approach can also be understood as finding a matrix
\(E\) where \(kEc^\intercal = \alpha \cdot s\).

When describing MA-ABE schemes in `ACABELLA`, we rely on the pair encodings extended by the Venema-Alpar
cryptanalysis framework:

- Global parameter encoding: or gp\(^{(b)}\), which consist of common variables \(b \in_R Z_p\).
- Master attribute-key encoding: or \(g^{mpk_a(b_{att}, b)}\), consisting of integers \(b_{att} \in_R Z_p\) and
encodings \(b\).
- User key encoding or \(k_u\), represented by \(h^{k_u(id, \alpha, r_u, b)}\) for user-specific random integers
\(r_u \in_R Z_p\).
- Attribute-independent ciphertext encodings: consisting of \(g^{c(s, b)}\) for ciphertext-specific random
\(s \in_R Z_p\).

## The AC17 analysis framework

The AC17 analysis framework [@ac17] studies the exponent space of the schemes (pair encodings) and relate it
to security notions. It shows that fully secure schemes can be constructed from
pair encodings that are provably symbolically secure. 

In the AC17 framework, Agrawal and Chase propose the symbolic security property for pair encodings and show that every predicated encryption scheme (that is, ABE included) that is not trivially broken should satisfy it.

### The symbolic property

If the pair encodings have this property, it means that it is possibe lo describe a mapping from the encoding variables to matrices and vectors. We should see that the polynomials in the encoding are evaluated to 0 when the variables are replaced. These matrices and vectors are generated by three deterministic algorithms in AC17:

- `EncB` generates matrices for common variables.
- `EncS` generates vectors for ciphertext encoding variables.
- `EncR` generates vectors for key encoding variables.

These entries are generated according to the type of security property we want to prove:

- `Selective property`: The three algorithms receive \(x\), `EncR` receives \(y\).
- `Co-selective property`: The three algorithms receive \(y\), `EncS` receives \(x\).

### The trivially broken property

This property means that there exist a way of combining the encoding polynomials in order to recover the blinding factor \(\alpha \cdot s\) for a particular message \(m\) with a false predicate.

We can see this property from predicated-based encryption as a way of recovering \(\alpha \cdot s\) via a matrix \(\mathbf{E}\), for inputs \(x, y\) that make \(P(x, y) = 0\) where \((s, c)\mathbf{E}(r, k)^{\intercal} = \alpha \cdot s\). 

## The FABEO property

In [@fabeo], the authors extend the symbolic property of [@ac17] in order to support many-ciphertext CPA security. Hence, the new property, `Strong Symbolic Security` includes:

- Many secret keys, ciphertexts and the public key.
- The adversay may ask for the same \(x, y\) multiple times.

# References
