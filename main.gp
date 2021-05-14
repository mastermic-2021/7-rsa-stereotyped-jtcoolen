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

/* OK, on va mettre en place une attaque stéréotypée (une partie du message est connue)
 * par le biais de la méthode de  Coppersmith en temps polynomial. On sait en effet
 * que le mot de passe inconnu (de longeur 10) et la clé publique RSA e=7 sont petits.
 * Description de l'attaque page 8 du rapport suivant (section Known modulus, la méthode
 * se généralisant à un module inconnu) :
 * https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/survey_final.pdf
 */

encode(m) = fromdigits(Vec(Vecsmall(m)), 128);
decode(m) = Strchr(digits(m, 128));

\\ Récupération de la clé publique RSA et du message chiffré:
parameters = readstr("input.txt");
key = eval(parameters[1]);
ciphertext = eval(parameters[2]);
n = key[1];
e = key[2];

begin = Vec(Vecsmall("Cher collaborateur, votre nouveau mot de passe est "));
end = Vec(Vecsmall(". Merci de votre comprehension, le service informatique."));
stereotype = encode(concat(begin, concat(Vec(0, 10), end)));

\\ Attaque reprise du manuel de PARI/GP, page 227
\\ https://pari.math.u-bordeaux.fr/pub/pari/manuals/2.13.0/users.pdf

X = 128^10; \\ Code inférieur à 128^10 car composé de 10 caractères. La borne est bien inférieure à n^(1/e).
/* Le message chiffré est de la forme stereotype + x * 128^#end,
 * on cherche donc les "petites" racines x du polynôme stereotype + x * 128^#end - ciphertext
 * On multiplie x par 128^#end car l'entier recherché correspondant au mot de passe
 * est décalé de #end charactères depuis la fin (le message est supposé codé en base 128).
 */
s = zncoppersmith((stereotype + 128^#end * x)^e - ciphertext, n, X);
print(Strprintf(template, decode(s[1])));

/* Vérification:
 * mail = Strprintf(template, "94aLGXO3sA");
 * m = fromdigits(Vec(Vecsmall(mail)),128);
 * c = lift(Mod(m,n)^e);
 * print(c);
 * print(c==ciphertext); \\ affiche 1
 */
