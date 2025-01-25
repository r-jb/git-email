<p align="center">
  <img src="https://raw.githubusercontent.com/r-jb/github-email-extractor/media/showcase.webp" alt="GitHub Email Extractor" height="500">
</p>

# GitHub Email Extractor

Extract email addresses from commit metadata.
This script supports GitHub users, organizations, and Git repositories.

## Installation

<details open><summary>Using wget</summary>

```bash
  wget https://raw.githubusercontent.com/r-jb/github-email-extractor/main/gh-email.sh
  chmod +x gh-email.sh
  ./gh-email.sh
```

</details>

<details><summary>Using curl</summary>

```bash
  curl -O https://raw.githubusercontent.com/r-jb/github-email-extractor/main/gh-email.sh
  chmod +x gh-email.sh
  ./gh-email.sh
```

</details>

## Requirements

> [!NOTE]
> By default, the script accesses GitHub's unauthenticated API, which is limited to 60 requests per hour. Authenticate using the [gh CLI](https://cli.github.com/) to increase this limit and scan private repos.

- bash 4+
- git
- curl
- awk or gawk, not mawk
- (Optional) [gh cli](https://cli.github.com/) authenticated

## Alternatives

- [emailaddress.github.io](https://emailaddress.github.io/)
- [Gitmails-sh](https://github.com/giovanifss/Gitmails-sh)
- [gitrecon](https://github.com/atiilla/gitrecon)
