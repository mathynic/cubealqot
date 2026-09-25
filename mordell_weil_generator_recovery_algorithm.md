# Mordell–Weil recovery: mathematical outline

This document describes the curve correspondence, an independence criterion,
the saturation goal, and the role of complete integral-point enumeration.

## The fixed-cofactor curve

For a fixed cofactor $N>1$, let

$$
A=\sigma(N^3),\qquad D=A-N^3>0.
$$

The family equation is

$$
y^2=Dq^3+A(q^2+q+1),\qquad q\text{ prime},\quad q\nmid N.
$$

The corresponding original elliptic curve is

$$
E_0:\quad Y^2=X^3+AX^2+ADX+AD^2,
$$

under $X=Dq$, $Y=Dy$. Rational points used as generators need not be integral
or satisfy the prime-family restrictions. Those restrictions apply when
filtering the complete integral-point set.

## Changes of model

Suppose a rational change of variables from a curve $E_m$ to $E_0$ has
parameters $v=[u,r,s,t]$, with $u\ne0$:

$$
X=u^2x+r,\qquad Y=u^3y+s u^2x+t.
$$

Its inverse is

$$
x=\frac{X-r}{u^2},\qquad
y=\frac{Y-s(X-r)-t}{u^3}.
$$

Points transported between the models must satisfy their curve equations
exactly. A rational change of variables need not preserve integrality, so the
complete integral-point set used for the family conclusion is on $E_0$.

## Independence from finite reductions

Let $P_1,\ldots,P_r\in E_m(\mathbb Q)$ for $r\in\{1,2\}$. Choose a prime
$\ell$ for which $E_m(\mathbb Q)$ has no rational $\ell$-torsion. For each
selected prime $p\ne\ell$ of good reduction at which the points reduce, write
$G_p=E_m(\mathbb F_p)$. Reduction followed by quotienting by
$\ell G_p=\{\ell R:R\in G_p\}$ defines

$$
\mathbb F_\ell^r\longrightarrow\prod_p G_p/\ell G_p,\qquad
(a_i)\longmapsto\left(\sum_i a_iP_i\bmod p\right)_p.
$$

If this map is injective, the $P_i$ are independent modulo rational torsion.
Otherwise a dependence could be divided by the greatest common divisor of its
coefficients to obtain a primitive nonzero coefficient vector. Its relation
would equal a torsion point. Since there is no rational $\ell$-torsion,
multiplication by $\ell$ is invertible on the rational torsion subgroup, so
the relation reduces into $\ell G_p$ at every selected prime. This contradicts
injectivity.

The absence of rational $\ell$-torsion can be witnessed by a good prime
$p_0\ne\ell$ for which $\ell\nmid\#E_m(\mathbb F_{p_0})$. Reduction at $p_0$
is injective on rational $\ell$-torsion, while the finite group has no element
of order $\ell$.

For rank one, the only nonzero coefficient direction is $(1)$. For rank two,
the projective directions over $\mathbb F_\ell$ are represented by

$$
(1,b),\quad b=0,\ldots,\ell-1,\qquad\text{and}\qquad(0,1).
$$

Eliminating every direction at some selected prime proves independence.
Failure to find such witnesses does not prove dependence.

## Rank and saturation

An upper bound $U$ for the rational rank must be justified independently of
the candidate points. If $U$ independent points have been established, they
generate a subgroup of full rank and finite index in the free part of
$E(\mathbb Q)$. Saturation enlarges that subgroup until its index is one;
independence alone does not establish that the subgroup is the full
Mordell–Weil group.

The final basis is transported to $E_0$, and the complete integral-point set
is enumerated on that original model. Each integral point $(X,Y)$ is filtered
by

$$
D\mid X,\qquad D\mid Y,\qquad q=X/D\ge2,\qquad
q\text{ prime},\qquad q\nmid N,
$$

and the exact equation $(Y/D)^2=F_N(X/D)$. Only this complete filtered set
determines the family solution set. Generator discovery alone establishes no
family conclusion.
