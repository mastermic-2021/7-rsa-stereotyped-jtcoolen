default(parisizemax, 70m);
/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
chpasswd(user,pwd) = {
  cmd = strprintf("yes %s | passwd %s",pwd,user);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
  }
template2 = {
  "Cher collaborateur, votre nouveau mot de passe est %s. ";
  }
change_password(user,modulus,e=7) = {
  iferr(
    pwd = randompwd(10);
    chpasswd(user, pwd);
    address = strprintf("%s@cryptoflop.org",user);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user ",user);
  ,E,print("[ERROR] ",E));
}

\\ OK, on va mettre en place une attaque stéréotypée (une partie du message est connue)
\\ par le biais de la méthode de  Coppersmith en temps polynomial. On sait en effet
\\ que le mot de passe inconnu (de longeur 10) et la clé publique RSA e=7 sont petits.
\\ Description de l'attaque page 8 du rapport suivant (section Known modulus, la méthode
\\ se généralisant à un module inconnu) :
\\ https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/survey_final.pdf

\\ Récupération de la clé publique RSA et du message chiffré:
encode(m) = fromdigits(Vec(Vecsmall(m)), 128);
decode(m) = Strchr(digits(m, 128));

parameters = readstr("input.txt");
key = eval(parameters[1]);
ciphertext = eval(parameters[2]);
n = key[1];
e = key[2];

\\print("ciphertext=", ciphertext);
print("\ne=", e, ", n=", n);

stereotype = encode("Cher collaborateur, votre nouveau mot de passe est xxxxxxxxxx. Merci de votre comprehension, le service informatique.");


\\ Attaque reprise du manuel de PARI/GP, page 227
\\ https://pari.math.u-bordeaux.fr/pub/pari/manuals/2.13.0/users.pdf
StereotypedAttack(n, e, c, stereotype) = {
  X = 1e26; \\ n^(1/e - epsilon)
  zncoppersmith((stereotype + x)^e - c, n, X);
}

\\print(StereotypedAttack(n, e, ciphertext, stereotype));

e = 7; \\ small public encryption exponent

\\print(decode(ciphertext));
X = 1e27;\\floor(n^(1/e)); \\ N^(1/e - epsilon)
x0 = encode("B1jTVFbKpP"); \\ unknown short message
\\print("msg1 = ", lift(Mod(stereotype1 + x0 + stereotype2, n)^e));
\\print("okay ", encode(Strprintf(template, "B1jTVFbKpP")), "\n");
\\print("msg1 = ", lift( (stereotype + Mod(x0, n))^e ));
\\print("\nmsg2 = ",lift(Mod(encode(Strprintf(template, "B1jTVFbKpP")), n)^e)); 
\\print("\nmsg2 = ", lift(Mod(encode(Strprintf(template, "B1jTVFbKpP")), n)^e)); 
C = lift( (stereotype + x0)^e); \\ known ciphertext, with padding P
\\print(lift(Mod(encode(Strprintf(template, "B1jTVFbKpP")), n)^e));
print(Strprintf(template,  "B1jTVFbKpP"), " ", encode(Strprintf(template,  "B1jTVFbKpP")));
print("\n", decode(stereotype), " ", stereotype);
print("diff=", logint(lift(Mod(stereotype-C, n)), 128));
print("diff=", logint(lift(Mod(stereotype-encode(Strprintf(template,  "B1jTVFbKpP")), n)), 128));
\\ différence de l'ordre de 1e65

\\ On exploite le fait que l'on connait la forme que prennent les mots de passe:
\\ chaines de caractère ASCII de longueur 10
\\ On génère des messages jusqu'à ce que la différence avec le chiffré soit suffisamment petite
\\ afin d'applique Coppersmith
StereotypedAttack(n, e, c) = {
  s = [];
  rpwd = "";
  diff = 40;
  X = 1E27;
  while(s == [],
    rpwd = randompwd(10);
    rand_msg = Strprintf(template, rpwd);
    rand_stereotype = lift(Mod(encode(rand_msg), n)^e);
    diff = logint(abs(lift(Mod(rand_stereotype - ciphertext, n))), 128);
    \\print(abs(lift(Mod(rand_stereotype - ciphertext, n))), " ", diff);
    s = zncoppersmith((rand_stereotype + x)^e - c, n, X);\\print(rand_msg, " ", s));
  );
  s = zncoppersmith((rand_stereotype + x)^e - c, n, X);\\print(rand_msg, " ", s));
  print(rpwd);
  print(decode(s[1]));
}

StereotypedAttack(n, e, ciphertext);
