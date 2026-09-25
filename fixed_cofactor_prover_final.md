# Fixed-cofactor family: mathematical formulation

This document states the family equation, its elliptic-curve model, and the
exact restrictions that characterize family solutions among integral points.

## Family equation

For an integer $n>1$, write

$$
n=\prod_i p_i^{e_i},\qquad
A=\sigma(n^3)=\prod_i\frac{p_i^{3e_i+1}-1}{p_i-1},\qquad
D=A-n^3.
$$

Since $n>1$, $D=s(n^3)>0$. For a prime $q\nmid n$, multiplicativity of the
divisor sum gives

$$
\begin{aligned}
s((nq)^3)
&=\sigma(n^3)\sigma(q^3)-(nq)^3\\
&=A(q^3+q^2+q+1)-n^3q^3\\
&=Dq^3+Aq^2+Aq+A.
\end{aligned}
$$

Thus, with

$$
F_n(q)=Dq^3+Aq^2+Aq+A,
$$

the family solutions are exactly the pairs $(q,y)$ satisfying

$$
q\text{ prime},\qquad q\nmid n,\qquad y\ge1,\qquad y^2=F_n(q).
$$

## Elliptic-curve correspondence

Set $X=Dq$ and $Y=Dy$. Multiplication by $D^2$ gives the curve

$$
E_n:\quad Y^2=X^3+AX^2+ADX+AD^2.
$$

Every family solution gives an integral point on $E_n$. Conversely, an
integral point $(X,Y)$ gives a family solution exactly when $D\mid X$,
$D\mid Y$, and the recovered values

$$
q=X/D,\qquad y=Y/D
$$

satisfy $q\ge2$, $q$ prime, $q\nmid n$, and $y\ge1$. The curve equation then
implies $y^2=F_n(q)$. The two signs of $Y$ give the same positive $y$; points
with $Y=0$ do not yield $y\ge1$.

The cubic on the right has discriminant

$$
\operatorname{disc}(X^3+AX^2+ADX+AD^2)
=-A^2D^2(3A^2-14AD+27D^2).
$$

The final factor is positive because

$$
3A^2-14AD+27D^2
=3\left(A-\frac{7D}{3}\right)^2+\frac{32D^2}{3}>0.
$$

Hence $E_n$ is nonsingular for $A,D>0$.

## Local obstruction

Suppose an integer $M\ge2$ has the property that $F_n(r)$ is a nonsquare
modulo $M$ for every residue $r\bmod M$ with $\gcd(r,M)=1$. Then no prime
$q\nmid M$ can satisfy $F_n(q)=y^2$. Only prime divisors of $M$ remain as
possible exceptions; each is checked in the original family equation.

## Completeness

The complete integral-point set of $E_n$, filtered by the divisibility and
prime conditions above, gives the complete solution set for cofactor $n$.
An empty filtered set means the family has no solutions. A nonempty set must
contain every qualifying prime $q$.
