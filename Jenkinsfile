pipeline {
    agent any
    environment {
    	GITLEAKS_VERSION = "v8.21.2"
  	SEMGREP_VERSION = "1.155.0"
	SYFT_VERSION = "v1.51.0" 
	GRYPE_VERSION = "v0.79.0" 
	TRIVY_VERSION = "0.58.2"
    }
    options {
    	timestamps()
	disableConcurrentBuilds()
	timeout(time: 30, unit: 'MINUTES')
	buildDiscarder(logRotator(numToKeepStr: '10', daysToKeepStr: '30'))
    }
    stages {
    	stage('checkout') {
		steps {
			checkout scm
		}
	}
        stage('fmt-lint-test') {
	    agent {
	        docker {
	        	image 'python:3.12.7-slim'
			reuseNode true
			args '-u root -v pip-cache:/root/.cache/pip'
	        }
	    }
	    environment {
	    	PIP_CACHE_DIR = '/root/.cache/pip'
	    }
            steps {
	    	sh 'python -m pip install -r app/requirements-dev.txt'
		sh 'python -m ruff check app'
		dir('app') {
			sh 'mkdir -p reports'
			sh 'python -m pytest -q --junitxml=reports/pytest.xml'
		}
            }
        }
	stage('secret-scan') {
		steps {
			sh 'mkdir -p reports'
			// continue on error, only for test
			catchError {
				sh """
				docker run --rm -v "$WORKSPACE:/src" -w /src \
					zricethezav/gitleaks:${env.GITLEAKS_VERSION} \
					git /src \
					-c /src/security/gitleaks.toml \
					--redact \
					--report-format sarif \
					--report-path /src/reports/gitleaks.sarif
				"""	
			}
		}
	}
	stage('SAST - semgrep') {
		steps {
			// continue on error, only for test
			catchError {
				sh """
				docker run --rm -v "$WORKSPACE:/src" -w /src \
					semgrep/semgrep:${env.SEMGREP_VERSION} \
					semgrep scan \
					--config p/security-audit \
					--config /src/security/semgrep \
					--metrics off \
					--sarif -o /src/reports/semgrep.sarif \
					/src
				"""
			}
		}
	}
	stage('SCA - syft+grype') {
		steps {
			catchError {
				sh """
				docker run --rm -v "$WORKSPACE:/src" -w /src \
				anchore/syft:${env.SYFT_VERSION} scan dir:. \
				-o cyclonedx-json --file /src/reports/sbom.cdx.json
				"""
				sh """
				docker run --rm -v "$WORKSPACE:/src" -w /src \
				anchore/grype:${env.GRYPE_VERSION} sbom:/src/reports/sbom.cdx.json \
				-o json --file /src/reports/grype.json
				"""
			}
		}
	}
    }
	post {
		always {
			junit 'app/reports/pytest.xml' // JUnit plugin
			archiveArtifacts artifacts: 'reports/gitleaks.sarif', allowEmptyArchive: true, fingerprint: true

			archiveArtifacts artifacts: 'reports/semgrep.sarif', allowEmptyArchive: true, fingerprint: true

			archiveArtifacts artifacts: 'reports/sbom.cdx.json', allowEmptyArchive: true, fingerprint: true

			archiveArtifacts artifacts: 'reports/grype.json', allowEmptyArchive: true, fingerprint: true
		}
		success { echo 'build OK' }
		failure { echo 'build failed!' }
		// cleanup {
		// 	cleanWs() // Workspace Cleanup Plugin
		// }
	}
}
