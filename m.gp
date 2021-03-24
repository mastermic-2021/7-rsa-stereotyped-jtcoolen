encode(m) = fromdigits(Vec(Vecsmall(m)), 128);

parameters = readstr("input.txt");
key = eval(parameters[1]);
ciphertext = eval(parameters[2]);
n = key[1];
e = key[2];

stereotype1 = encode("Cher collaborateur, votre nouveau mot de passe est ");
stereotype2 = encode(". Merci de votre comprehension, le service informatique.");
\\ Attaque reprise du manuel de PARI/GP, page 227
\\ https://pari.math.u-bordeaux.fr/pub/pari/manuals/2.13.0/users.pdf

e = 7; \\ small public encryption exponent

X = 200;\\floor(n^(1/e)); \\ N^(1/e - epsilon)
x0 = 12; \\ unknown short message
C = lift( (stereotype1 + Mod(x0,n) + stereotype2)^e ); \\ known ciphertext, with padding P
print(zncoppersmith((stereotype1 + x + stereotype2)^e - C, n, X), " ", x0);
