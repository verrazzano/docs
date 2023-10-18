 // Copyright (c) 2020, 2023 Oracle and/or its affiliates.

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
            label "pipeline-job-single-large"
        }
    }

    parameters {
        booleanParam (name: 'PUBLISH_TO_GH_PAGES',
                defaultValue: false,
                description: 'When true, builds the production website and pushes to the gh-pages branch')
    }

    environment {
        GIT_AUTH = credentials('github-packages-credentials-rw')
        EMAIL = credentials('github-packages-email')
    }

    stages {
        stage('Setup Dependencies') {
            steps {
                sh """
                    npm install
                """
            }
        }

        stage('Build staging documentation') {
            steps {
                sh """
                    mkdir -p staging
                    hugo --source . --destination staging --environment staging
                """
            }
        }

        stage('Build production documentation') {
            steps {
                sh """
                    mkdir -p production
                    env HUGO_ENV=production hugo --source . --destination production --environment production
                """
            }
        }

        stage('Publish documentation to gh-pages') {
            when {
                anyOf {
                    branch 'master'
                    equals expected: true, actual: params.PUBLISH_TO_GH_PAGES
                }
            }
            steps {
                sh """
                    echo "run site publisher"
                    ./scripts/publish.sh "${env.BRANCH_NAME}"
                """
            }
        }

        stage('Creating production documentation zip') {
            steps {
                sh """
                    zip -r verrazzano-production-docs.zip production
                """
            }
        }

        stage('Archive artifacts ') {
            steps {
               archiveArtifacts artifacts: 'staging/**'
               archiveArtifacts artifacts: 'production/**'
               archiveArtifacts artifacts: 'verrazzano-production-docs.zip'
            }
        }

    }
}
