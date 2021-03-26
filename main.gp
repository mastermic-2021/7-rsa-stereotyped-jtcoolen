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

encode(m) = fromdigits(Vec(Vecsmall(m)), 128);
decode(m) = {
  d = digits(m, 128);
  for(i = 1, #d, d[i] = d[i]+32); \\ on ajoute 32 qui correspond au code espace
  Strchr(d);
}


\\ Récupération de la clé publique RSA et du message chiffré:
parameters = readstr("input.txt");
key = eval(parameters[1]);
ciphertext = eval(parameters[2]);
n = key[1];
e = key[2];

stereotype = encode("Cher collaborateur, votre nouveau mot de passe est           . Merci de votre comprehension, le service informatique.");

\\ Attaque reprise du manuel de PARI/GP, page 227
\\ https://pari.math.u-bordeaux.fr/pub/pari/manuals/2.13.0/users.pdf

X = 1E27; \\ borne pour les racines, déterminée empiriquement mais inférieure à n^(1/e)
\\ Le message chiffré est de la forme stereotype + x * 128^56,
\\ on cherche donc les racines x du polynôme  stereotype + x * 128^56 - ciphertext
\\ On multiplie x par 128^56 car l'entier recherché correspondant au mot de passe
\\ est décalé de 56 charactères depuis la fin (le message est supposé codé en base 128).
s = zncoppersmith((stereotype + 128^56 * x)^e - ciphertext, n, X);
\\print(s);
print(Strprintf(template, decode(s[1])));

\\ Vérification:
mail = Strprintf(template, "94aLGXO3sA");
m = fromdigits(Vec(Vecsmall(mail)),128);
c = lift(Mod(m,n)^e);
\\print(c);
\\print(c==ciphertext); \\ affiche 1
