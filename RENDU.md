# Projet Sécurité du Web

## Membres du groupes
- LOUNADI Nassim
- DEHIL Sami

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
