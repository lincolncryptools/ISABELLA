
# Bridge to the ABGW17 analyzer

In [ABGW17], the authors provided a tool for analyzing the security
of ABE schemes within the context of the group generic model. In ACABELLA,
we provide a bridge to also obtain the output of the analysis of the ABGW tool.

The bridge is composed of two modules:

1. A command line tool: Located at `tools/abgw_bridge`, it receives a description
of an ABE scheme written in JSON, for instance, for the YJR13 scheme:

```json
{
    "scheme_id": "yjr13",
    "analysis": "abgw",
    "k": ["a * (1 / x1) + x2 * b + r * (b / bp)", "r * bp * (1 / x1)", "r * b"],
    "c": ["s", "s / bp"],
    "mpk": ["bp"],
    "gp": ["b"],
    "key" : "a * s",
    "unknown_vars" :  ["a", "r", "s", "b", "bp"],
    "known_vars" : ["x1", "x2"]
}
```

It can be used to obtain the corresponding input for ABGW, for instance:

```bash
$ python abgw_bridge_cmd.py example.json 
[*] ABGW bridge cmd tool
[!] Processing example.json

params c1,c2,c3,c4,c5,c6 in Zp.
vars a,r,s,b,bp in Zp.
params x1,x2 in Zp.


c1*(a*s/x1 + b*s*x2 + b*r*s/bp) +
c2*(a*s/(bp*x1) + b*s*x2/bp + b*r*s/bp*bp) +
c3*(bp*r*s/x1) +
c4*(r*s/x1) +
c5*(b*r*s) +
c6*(b*r*s/bp)
= a * s.

go.
```

2. A dockerized version of the ABGW tool. Located at `tools/abgw_docker`, it invokes the ABGW tool with ABE schemes defined in the `solver_inputs` directory.
Note that the `build_and_run.sh` script compiles the image defined in the docker file and launch a container image where ABGW is executed.

For instance:

```bash
$ ./build_and_run.sh               
Sending build context to Docker daemon  48.13kB
Step 1/27 : FROM ubuntu:16.04
 ---> b6f507652425
Step 2/27 : RUN apt update -y
 ---> Using cache
 ---> 1688783f3dcc
Step 3/27 : RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
 ---> Using cache
 ---> 0dbe43f37870
Step 4/27 : RUN apt-get install -y tzdata
 ---> Using cache
 ---> e3f3790737f4
Step 5/27 : RUN dpkg-reconfigure --frontend noninteractive tzdata
 ---> Using cache
 ---> e6d34b8176ad
Step 6/27 : RUN apt-get --assume-yes install software-properties-common
 ---> Using cache
 ---> 9ed00e1180b3
Step 7/27 : RUN echo "export GGM_PATH=/root/ggm-symbolic-solver" >> /etc/bash.bashrc
 ---> Using cache
 ---> c09a02d4d6f1
Step 8/27 : RUN apt install git vim build-essential sudo python3-dev wget flex bison python3-pip libssl-dev libgmp10 libgmp-dev git openssl -y
 ---> Using cache
 ---> 0107f2df09fb
Step 9/27 : RUN apt-get install -y curl ocaml ocaml-native-compilers opam libtool libtool-bin libgmp-dev libffi-dev m4 libz-dev libssl-dev camlp4-extra
 ---> Using cache
 ---> 629689e6d19b
Step 10/27 : WORKDIR /root
 ---> Using cache
 ---> d79f0bee8e6f
Step 11/27 : RUN git clone https://github.com/miguel-ambrona/ggm-symbolic-solver
 ---> Using cache
 ---> 1a87191dcd28
Step 12/27 : WORKDIR /root/ggm-symbolic-solver
 ---> Using cache
 ---> d9117f162a43
Step 13/27 : RUN opam init --yes
 ---> Using cache
 ---> ea83d8958f44
Step 14/27 : RUN eval `opam config env`
 ---> Using cache
 ---> 3744bac4bc53
Step 15/27 : RUN opam pin add symbolic-solver . -n --yes
 ---> Using cache
 ---> 57ee5bb1a57a
Step 16/27 : RUN opam install symbolic-solver --deps-only --yes
 ---> Using cache
 ---> d151dd1a053f
Step 17/27 : RUN export GGM_PATH=/root/ggm-symbolic-solver/
 ---> Using cache
 ---> fc1963909dd5
Step 18/27 : RUN apt-add-repository -y ppa:aims/sagemath
 ---> Using cache
 ---> d74a3b71a915
Step 19/27 : RUN apt-get update -y
 ---> Using cache
 ---> e66d9de8839d
Step 20/27 : RUN apt-get --assume-yes install sagemath-upstream-binary
 ---> Using cache
 ---> 0dc912223b53
Step 21/27 : COPY ggm_setup.sh/ .
 ---> Using cache
 ---> 54581c89d3eb
Step 22/27 : RUN chmod +x ggm_setup.sh
 ---> Using cache
 ---> 99be81b5d1b0
Step 23/27 : RUN ./ggm_setup.sh
 ---> Using cache
 ---> 2caff98e273d
Step 24/27 : RUN rm -rf examples/*
 ---> Using cache
 ---> ff8f9b8c477b
Step 25/27 : COPY solver_inputs/* examples/
 ---> Using cache
 ---> 4df8886f035e
Step 26/27 : COPY changes/* .
 ---> Using cache
 ---> c62e8b35a2c7
Step 27/27 : CMD ["/bin/bash"]
 ---> Using cache
 ---> eb18b1849e3d
Successfully built eb18b1849e3d
Successfully tagged abeattacks:latest


[*] Now run run_examples.py

root@5f232cb06e7c:~/ggm-symbolic-solver# 
root@5f232cb06e7c:~/ggm-symbolic-solver# ./run_examples.py 

Initialized solver!

./examples/cp_abe_ndcw15.ggm  Complete output:
\begin{aligned} & \text{sets:} && \emptyset\\ & \text{parameters:} && \color{#ccee77}{d_{1}}, \color{#ccee77}{d_{2}}, \color{#ccee77}{d_{3}}, \color{#ccee77}{c_{1}}, \color{#ccee77}{c_{2}}, \color{#ccee77}{c_{3}}, \color{#ccee77}{c_{4}}, \color{#ccee77}{c_{5}}, \color{#ccee77}{c_{6}}, \color{#ccee77}{c_{7}}, \color{#ccee77}{c_{8}}, \color{#ccee77}{c_{9}}, \color{#ccee77}{c_{10}}, \color{#ccee77}{c_{11}}, \color{#ccee77}{c_{12}} \in \mathbb{Z}_p^{} \\  & \text{variables:} && \color{#dd83f9}{a}, \color{#dd83f9}{b_{1}}, \color{#dd83f9}{b_{2}}, \color{#dd83f9}{s} \in \mathbb{Z}_p^{} \\  \\ & \text{goal }1 \text{ out of } 1 \end{aligned}@\begin{aligned}(1) \  & \color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (2) \  &  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (3) \  &  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} +  20  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} +  20  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (4) \  &  20  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (5) \  &  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (6) \  &  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}} + \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} + \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (7) \  & \color{#ccee77}{c_{5}}\color{#ccee77}{d_{1}} + \color{#ccee77}{c_{7}}\color{#ccee77}{d_{1}}=0& & \land \\ (8) \  & \color{#ccee77}{c_{8}}\color{#ccee77}{d_{1}}=0& & \land \\ (9) \  & \color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (10) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (11) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (12) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (13) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (14) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}}=0& & \land \\ (15) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}=0& & \land \\ (16) \  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}=0& & \land \\ (17) \  & \color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}} +  20  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}} +  15  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#dd83f9}{b_{1}}\color{#dd83f9}{b_{1}} +  6  \ \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#dd83f9}{b_{1}} + \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\neq0 \\  & & \\  & \color{#ccee77}{c_{1}}\mapsto \color{#ccee77}{d_{3}} & & \\  & \color{#ccee77}{c_{2}}\mapsto  1  & & \\  & \color{#ccee77}{d_{2}}\mapsto \left( -1 \right)\color{#ccee77}{c_{6}}\color{#ccee77}{d_{1}} + \left( -6 \right)\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}} & & \\  & \color{#ccee77}{c_{3}}\mapsto 0 \\  & & \\  & \color{#ccee77}{c_{8}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{4}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\mapsto 0 & & \\  & \color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{c_{9}}\color{#ccee77}{d_{1}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\color{#ccee77}{d_{3}}\mapsto 0\end{aligned}

Not proven        Time: 2.043
./examples/cp_abe_yjr13.ggm   Complete output:
\begin{aligned} & \text{sets:} && \emptyset\\ & \text{parameters:} && \color{#ccee77}{c_{1}}, \color{#ccee77}{c_{2}}, \color{#ccee77}{c_{3}}, \color{#ccee77}{c_{4}}, \color{#ccee77}{c_{5}}, \color{#ccee77}{c_{6}}, \color{#ccee77}{x_{1}}, \color{#ccee77}{x_{2}} \in \mathbb{Z}_p^{} \\  & \text{variables:} && \color{#dd83f9}{a}, \color{#dd83f9}{r}, \color{#dd83f9}{s}, \color{#dd83f9}{b}, \color{#dd83f9}{bp} \in \mathbb{Z}_p^{} \\  \\ & \text{goal }1 \text{ out of } 1 \end{aligned}@\begin{aligned}(1) \  & \color{#ccee77}{c_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}} + \left( -1 \right)\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}=0& & \land \\ (2) \  & \color{#ccee77}{x_{1}}\color{#ccee77}{c_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}} + \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{6}}=0& & \land \\ (3) \  & \color{#ccee77}{c_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}=0& & \land \\ (4) \  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{3}}\color{#ccee77}{x_{1}}=0& & \land \\ (5) \  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{4}}=0& & \land \\ (6) \  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{5}}=0& & \land \\ (7) \  & \color{#ccee77}{c_{2}}\color{#ccee77}{x_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}=0& & \land \\ (8) \  & \color{#ccee77}{x_{1}}\color{#ccee77}{c_{1}}\color{#ccee77}{x_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}=0& & \land \\ (9) \  & \color{#ccee77}{x_{1}}\neq0& & \land \\ (10) \  & \color{#dd83f9}{bp}\neq0 \\  \\  & & \\  & \color{#ccee77}{c_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\mapsto 0 & & \\  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{3}}\color{#ccee77}{x_{1}}\mapsto 0 & & \\  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{4}}\mapsto 0 & & \\  & \color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{c_{5}}\mapsto 0 & & \\  & \color{#ccee77}{c_{2}}\color{#ccee77}{x_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\mapsto 0 & & \\  & \color{#ccee77}{x_{1}}\color{#ccee77}{c_{1}}\color{#ccee77}{x_{2}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\color{#ccee77}{x_{1}}\mapsto 0\end{aligned}

Not proven        Time: 0.037
root@5f232cb06e7c:~/ggm-symbolic-solver# 
```
