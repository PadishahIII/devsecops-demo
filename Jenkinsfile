pipeline {
    agent any
    environment {
    	GITLEAKS_VERSION = "v8.21.2"
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
	    docker {
	    	image 'python:3.12.7-slim'
		reuseNode true
		args '-v pip-cache:/root/.cache/pip'
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
			// continue on error
			catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
				sh """
				docker run --rm -v "$WORKSPACE:/src" -w /src \
					gitleaks/gitleaks:${env.GITLEAKS_VERSION} \
					git /src \
					-c /src/security/gitleaks.toml \
					--redact \
					--report-format sarif \
					--report-path /src/reports/gitleaks.sarif
				"""	
			}
		}
	}
    }
	post {
		always {
			junit 'app/reports/pytest.xml' // JUnit plugin
			archiveArtifacts artifacts: 'reports/gitleaks.sarif', allowEmptyArchive: true, fingerprint: true
		}
		success { echo 'build OK' }
		failure { echo 'build failed!' }
		// cleanup {
		// 	cleanWs() // Workspace Cleanup Plugin
		// }
	}
}
