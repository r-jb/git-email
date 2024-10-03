<p align="center"><img src="https://raw.githubusercontent.com/r-jb/github-email-extractor/media/showcase.webp" alt="GitHub Email Extractor" height="500"></p>

# GitHub Email Extractor

Extract and compile email addresses from GitHub users, organizations, and Git repositories, all from commit metadata.

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

- bash 4+
- git
- curl
- awk or gawk, not mawk
- (Optional) [gh cli](https://cli.github.com/) authenticated

> [!NOTE]
> By default, the script use accesses GitHub's API unauthenticated, which is limited to 60 requests per hour. Use the [gh CLI](https://cli.github.com/) to authenticate and increase this limit.
