 // Copyright (c) 2020, Oracle Corporation and/or its affiliates. 

pipeline {
    options {
      disableConcurrentBuilds()
    }

    agent {
    
        docker {
            label 'VM.Standard2.8'
            image 'oraclelinux:8-slim'
            args '-u root:root -v /publish:${WORKSPACE}/publish/'
        }
    }

    stages {
        stage('Setup Hugo') {
            steps {
                sh """
                    microdnf install -y wget git tar
                    wget https://github.com/gohugoio/hugo/releases/download/v0.68.3/hugo_extended_0.68.3_Linux-64bit.tar.gz
                    tar xzvf hugo_extended_0.68.3_Linux-64bit.tar.gz hugo
                    mv hugo /bin
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

