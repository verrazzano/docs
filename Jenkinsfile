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
        string (name: 'API_BRANCH',
                defaultValue: 'master',
                description: 'Identifies the branch used to generate the Verrazzano API docs',
                trim: true)
   }

    environment {
        GIT_AUTH = credentials('github-packages-credentials-rw')
        EMAIL = credentials('github-packages-email')
    }

    stages {
        stage('Build API reference documentation') {
            when {
                not {
                    anyOf {
                        branch 'master';
                        branch 'release-*'
                    }
                }
            }
            steps {
                sh """
                    git config --global credential.helper "!f() { echo username=\\$GIT_AUTH_USR; echo password=\\$GIT_AUTH_PSW; }; f"
                    git config --global user.name $GIT_AUTH_USR
                    git config --global user.email "${EMAIL}"
                    git checkout ${env.BRANCH_NAME}
                """
                rc = sh(script: "./scripts/genapidocs/genapidocs.sh ${params.API_BRANCH}", returnStatus: true)
                sh """
                    echo \"exit code is : ${rc}\""

                    git status
                """
//                    ./scripts/genapidocs/genapidocs.sh ${params.API_BRANCH}
//                sh """
//                   git add deploy/operator.yaml
//                   git commit -m "[verrazzano] Update verrazzano-platform-operator image version to ${DOCKER_IMAGE_TAG} in operator.yaml"
//                   git push origin ${env.BRANCH_NAME}
//               """
            }
        }

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
                    # This is a workaround to include the documentation to setup private registry using both lite and
                    # full distribution
                    mkdir -p public
                    cp content/en/docs/setup/private-registry/private-registry-full-distribution.md content/en/docs/setup/private-registry/private-registry.md
                    env HUGO_ENV=production hugo --source . --destination public --environment production
                    zip -r verrazzano-production-docs.zip public
                """
            }
        }

        stage('Archive artifacts ') {
            steps {
               archiveArtifacts artifacts: 'staging/**'
               archiveArtifacts artifacts: 'production/**'
               archiveArtifacts artifacts: 'public/**'
               archiveArtifacts artifacts: 'verrazzano-production-docs.zip'
            }
        }

    }
}
