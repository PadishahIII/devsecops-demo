# docker-cd — Jenkins shared library

Shared library used by `Jenkinsfile.cd` to build & push Docker images.

## Layout

```
deploy/jenkins/shared-libs/docker-cd/
├── vars/
│   └── dockerBuildPush.groovy   # the single reusable step
└── src/
    └── dockercd/
        └── Versions.groovy      # library version (package dockercd)
```

## Steps

### dockerBuildPush

```groovy
dockerBuildPush(
    registry:   'docker.io',                // optional, default docker.io
    repository: 'padishahiii/devsecops-demo',
    dockerfile: 'app/Dockerfile',           // path relative to $WORKSPACE
    context:    'app',                      // build context
    tags:       ['latest'],                 // extra tags (default tag is added automatically)
    push:       true,                       // set false to build only
)
```

- Resolves the git commit (`git rev-parse --short=8 HEAD`) and build number itself,
  so every image is tagged `<sha8>-<BUILD_NUMBER>` — reproducible and traceable.
- `tags` are extra tags added on top of the default.
- Pushes via `docker login` (stdin) using `DOCKERHUB_CRED_USR` / `DOCKERHUB_CRED_PSW`
  bound from a Jenkins **Username/Password** credential (id `dockerhub`).
- Requires the **Docker Pipeline** plugin (`withDockerRegistry`, `docker.build`,
  `docker.push` steps) and **Credentials Binding** (bundled).

## Jenkins setup

1. Manage Jenkins → System → **Global Pipeline Libraries** → Add:
   - Name: `docker-cd`, Default version: `main`
   - Retrieval: Modern SCM → Git → this repository (devsecops-demo)
   - Library path: `deploy/jenkins/shared-libs/docker-cd`
2. Manage Jenkins → Credentials → Add **Username/Password** credential
   - ID: `dockerhub`, username + password (or access token) for Docker Hub
3. Create a **Pipeline** job (not Multibranch):
   - Definition: Pipeline script from SCM
   - Script path: `Jenkinsfile.cd`
   - Branch: `main`
4. Build with parameters: `REPOSITORY`, `BRANCH`, `IMAGE_TAG`, `PUSH_IMAGE`.

The pipeline is **manual**: it does not auto-trigger on push. It uses
`parameters { ... }` so the job dialog offers the same knobs as the Jenkinsfile.cd
`properties()` — keep both in sync if you change parameter names.

## Notes

- `docker.io` is resolved to Docker Hub; a Docker Hub account with push access to
  `REPOSITORY` is required.
- Library version `1.0.0` (see `src/dockercd/Versions.groovy`).
