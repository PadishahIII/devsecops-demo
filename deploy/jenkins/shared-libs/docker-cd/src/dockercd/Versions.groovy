#!/usr/bin/env groovy
// Global shared library for the Jenkins CD pipeline.
//
// How Jenkins finds this library:
//   Global Pipeline Libraries (Manage Jenkins → System):
//     - Name:            docker-cd
//     - Default version: main
//     - Retrieval:       Modern SCM → Git
//     - Project repo:    this repository (devsecops-demo)
//     - Library path:    deploy/jenkins/shared-libs/docker-cd
//
// Then in Jenkinsfile.cd:  @Library('docker-cd') _
package dockercd

// Version of this library, surfaced in the pipeline log.
def version() {
    return '1.0.0'
}
