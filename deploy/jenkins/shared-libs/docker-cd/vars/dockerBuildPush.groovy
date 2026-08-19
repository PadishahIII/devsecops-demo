// dockerBuildPush — build a Docker image and push it to a registry.
//
// Usage (Jenkinsfile.cd):
//   dockerBuildPush(
//     registry:    'docker.io',                // registry host, default 'docker.io'
//     repository:  'youruser/devsecops-demo',  // registry-relative repository name
//     dockerfile:  'app/Dockerfile',           // path relative to $WORKSPACE
//     context:     'app',                      // build context (default: dir of dockerfile)
//     tags:        ['latest'],                 // extra tag(s) on top of the default
//     push:        true,                       // push after build (default true)
//   )
//
// The step resolves the current git commit and build number itself, so callers
// only supply the *suffix* tags they want on top of the default:
//   defaultTag = '<sha8>-<BUILD_NUMBER>'      (always included)
//   extraTag   = 'latest' on main             (caller decides)
//
// Credentials: expects a Username/Password credential bound into the
// environment as DOCKERHUB_USERNAME / DOCKERHUB_PASSWORD (see Jenkinsfile.cd).
// Uses the Docker Pipeline plugin (`docker` global) — requires that plugin.
//
// Registry login:
//   - if DOCKERHUB_USERNAME/DOCKERHUB_PASSWORD are set, logs in via the docker CLI
//     (stdin) before building, so both build (base image pulls) and push work.
//   - otherwise builds only; push errors out with a clear message.

def call(Map args) {
    def registry   = args.registry ?: 'docker.io'
    def repository = args.repository
    def dockerfile = args.dockerfile ?: 'Dockerfile'
    def context    = args.context ?: new File(dockerfile).getParent() ?: '.'
    def extraTags  = args.tags ?: []
    def shouldPush = args.containsKey('push') ? args.push : true

    if (!repository) {
        error 'dockerBuildPush: `repository` is required (e.g. "youruser/devsecops-demo")'
    }

    def commit = sh(
        script: 'git rev-parse --short=8 HEAD',
        returnStdout: true
    ).trim()

    def buildNum = env.BUILD_NUMBER ?: '0'

    // default tag: <commit-sha8>-<build-number> — always reproducible
    def tags = ["${commit}-${buildNum}"] + extraTags

    // docker.login() + docker.push() from the Docker Pipeline plugin.
    // withRegistry('https://docker.io') matches the default registry context.
    withRegistry("https://${registry}") {
        // login if we have credentials; this also covers private base-image pulls
        if (env.DOCKERHUB_USERNAME && env.DOCKERHUB_PASSWORD) {
            sh """
                set -e
                echo "\$DOCKERHUB_PASSWORD" | docker login ${registry} --username "\$DOCKERHUB_USERNAME" --password-stdin
            """
        }

        stage("Docker build ${repository}") {
            // NOTE: first arg is repository[:tag] (no registry prefix), second
            // arg is the full `docker build` CLI tail (dockerfile + context).
            docker.build("${repository}:${tags[0]}", "--file ${dockerfile} ${context}")
        }

        if (shouldPush) {
            if (!env.DOCKERHUB_USERNAME || !env.DOCKERHUB_PASSWORD) {
                error 'dockerBuildPush: push requested but DOCKERHUB_USERNAME/DOCKERHUB_PASSWORD not set — bind a Username/Password credential (id `dockerhub`) in the pipeline'
            }
            stage("Docker push ${repository}") {
                // push default tag, then re-tag + push each extra tag
                def image = docker.image("${repository}:${tags[0]}")
                image.push()
                for (tag in tags.tail()) {
                    // docker.tag(oldImage:..., newImage:...) then push
                    // (docker.tag is available on Docker Pipeline plugin 1.24+)
                    sh "docker tag ${repository}:${tags[0]} ${registry}/${repository}:${tag}"
                    docker.image("${registry}/${repository}:${tag}").push()
                }
            }
        }
    }

    // convenience: expose the default image name for downstream steps
    env.DOCKER_IMAGE = "${registry}/${repository}:${tags[0]}"
    return ["${registry}/${repository}:${tags[0]}"] + tags.tail().collect { "${registry}/${repository}:${it}" }
}
