 // Copyright (c) 2020, Oracle Corporation and/or its affiliates. 

pipeline {
    options {
      disableConcurrentBuilds()
    }

    agent {
    
        docker {
            image "phx.ocir.io/stevengreenberginc/verrazzano/jenkins-runner-ci-jenkins:11"
            args "${RUNNER_DOCKER_ARGS}"
            registryUrl "${RUNNER_DOCKER_REGISTRY_URL}"
            registryCredentialsId 'ocir-pull-and-push-account'
        }
    }

    stages {
        stage('Setup Dependencies') {
            steps {
                sh """
                    npm install
                """
            }
        }

        stage('Build documentation') {
            steps {
                sh """
                    mkdir -p public/docs
                    hugo --source . --destination public
                """
            }
        }

        stage('Publish documentation') {
            when {
                branch pattern: "master"
            }
            steps {
                archiveArtifacts artifacts: 'public/**'
            }
        }
    }
}

