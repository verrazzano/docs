 // Copyright (c) 2020, Oracle Corporation and/or its affiliates. 

pipeline {
    options {
      disableConcurrentBuilds()
    }

    agent {
    
        docker {
            image "${RUNNER_DOCKER_IMAGE}"
            args "${RUNNER_DOCKER_ARGS}"
            registryUrl "${RUNNER_DOCKER_REGISTRY_URL}"
            registryCredentialsId 'ocir-pull-and-push-account'
        }
    }

    stages {
        stage('Setup Hugo') {
            steps {
                sh """
                    sudo yum -y install gcc-c++
                    curl -L https://github.com/gohugoio/hugo/archive/v0.74.3.tar.gz | tar zxvf -
                    cd hugo-0.74.3
                    go install
                """
            }
        }

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

