 // Copyright (c) 2020, 2021 Oracle and/or its affiliates. 

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

                    # This is a workaround to conditionally include the documentation to setup private registry differently
                    # for full distribution and lite distribution
                    mkdir private-registry-full-distribution
                    mv production/docs/setup/private-registry/private-registry-full-distribution/* ${WORKSPACE}/private-registry-full-distribution
                    rm -rf production/docs/setup/private-registry/private-registry-full-distribution
                """
            }
            post {
                always {
                    archiveArtifacts artifacts: 'production/**'
                }
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
                    cp private-registry-full-distribution/index.html production/docs/setup/private-registry/private-registry/index.html
                    rm -rf private-registry-full-distribution
                    zip -r verrazzano-production-docs.zip production
                """
            }
        }

        stage('Archive artifacts ') {
            steps {
               archiveArtifacts artifacts: 'staging/**'
               archiveArtifacts artifacts: 'verrazzano-production-docs.zip'
            }
        }
    }
}
