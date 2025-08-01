pipeline {
    agent any
    environment{
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_REGISTRY = 'didin8080'
        IMAGE_NAME = "lapzone"
        IMAGE_FULL_NAME = "didin8080/lapzone"
    }
    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
       stage('Checkout from GitHub') {
            steps {
                git branch: 'main', url: 'https://github.com/didin2003/lapzone.git'
                script {
                    def hash = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    def timestamp = new Date().format('yyyyMMddHHmmss')
                    env.COMMIT_HASH = hash
                    env.IMAGE_VERSION = "${hash}-${timestamp}"
                }
            }
       }
        stage('Sonarqube analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh """
                        $SCANNER_HOME/bin/sonar-scanner \
                        -Dsonar.projectKey=lapzone \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=http://44.202.15.23:9000 \
                      """
                }
            }
        }
        stage('quality gate') {
            steps {
                waitForQualityGate abortPipeline: false, credentialsId: 'sonar-token'
            }
        }
        stage('Trivy Filesystem Scan') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                        def template = fileExists('html.tpl') ? '@html.tpl' : 'table'
                        sh """
                            mkdir -p ${TRIVY_CACHE_DIR}
                            trivy fs --scanners vuln,misconfig --cache-dir ${TRIVY_CACHE_DIR} \
                                --format template --template ${template} -o trivy-fs-report.html . || echo "Trivy FS scan completed with findings"
                        """
                        archiveArtifacts artifacts: 'trivy-fs-report.html'
                        def fsReport = readFile('trivy-fs-report.html')
                        env.FS_SCAN_CRITICAL = fsReport.contains('CRITICAL') ? 'Yes' : 'No'
                        if (env.FS_SCAN_CRITICAL == 'Yes') {
                            error("Critical vulnerabilities found in filesystem scan")
                        }
                    }
                }
            }
        }
        stage('Build and tag docker image') {
            steps {
                sshagent(['ssh-docker']) {
                    sh """
                         ssh -o StrictHostKeyChecking=no ubuntu@44.202.15.23 << 'EOF'
                             set -e
                             cd /home/ubuntu
                             rm -rf lapzone || true
                             git clone https://github.com/didin2003/lapzone.git
                             cd lapzone
                             git pull origin main
                             docker build -t ${IMAGE_FULL_NAME}:${IMAGE_VERSION} .
                             docker tag ${IMAGE_FULL_NAME}:${IMAGE_VERSION} ${IMAGE_FULL_NAME}:latest
EOF
                     """
                 }
            }
        }
        stage('Trivy Image Scan (Remote)') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                        sshagent(['ssh-docker']) {
                            sh """
                                ssh -o StrictHostKeyChecking=no ubuntu@44.202.15.23 << 'EOF'
                                mkdir -p ~/trivy-cache
                                trivy image --scanners vuln,misconfig --cache-dir ~/trivy-cache \
                                    --format html -o trivy-image-report.html ${IMAGE_FULL_NAME}:${IMAGE_VERSION} || echo "Scan completed with findings"
EOF
                                scp -o StrictHostKeyChecking=no ubuntu@44.202.15.23:~/trivy-image-report.html .
                            """
                        }
                        archiveArtifacts artifacts: 'trivy-image-report.html'
                        def imageReport = readFile('trivy-image-report.html')
                        env.IMAGE_SCAN_CRITICAL = imageReport.contains('CRITICAL') ? 'Yes' : 'No'
                        if (env.IMAGE_SCAN_CRITICAL == 'Yes') {
                            error("Critical vulnerabilities found in image scan")
                        }
                    }
                }
            }
        }
        stage('Push Docker Image (Remote)') {
            steps {
               withCredentials([string(credentialsId: 'docker', variable: 'DOCKER_TOKEN')]) {
                    sshagent(['ssh-docker']) {
                        sh """
                            ssh -o StrictHostKeyChecking=no ubuntu@44.202.15.23 << 'EOF'
                                set -x
                                mkdir -p ~/.docker
                                echo '{ "credsStore": "" }' > ~/.docker/config.json
                                echo "${DOCKER_TOKEN}" | docker login -u didin8080 --password-stdin
                                docker images
                                docker push ${IMAGE_FULL_NAME}:${IMAGE_VERSION} || true
                                docker push ${IMAGE_FULL_NAME}:latest
EOF
                        """
                    }
                }
            }
        }
        stage('Deploy to Cloud Instance') {
            steps {
                sshagent(['ssh-docker']) {
                    sh """
                        ssh -o StrictHostKeyChecking=no ubuntu@44.202.15.23 << 'EOF'
                            docker pull ${IMAGE_FULL_NAME}:latest
                            docker stop lapzone-container || true
                            docker rm lapzone-container || true
                            docker run -d --name lapzone-container -p 8000:8000 --restart unless-stopped ${IMAGE_FULL_NAME}:latest
EOF
                    """
                }
            }
        }
    }
    post {
    always {
        emailext attachLog: true,
            subject: "'${currentBuild.result}'",
            body: """
                <html>
                <body>
                    <div style="background-color: #FFA07A; padding: 10px; margin-bottom: 10px;">
                        <p style="color: white; font-weight: bold;">Project: ${env.JOB_NAME}</p>
                    </div>
                    <div style="background-color: #90EE90; padding: 10px; margin-bottom: 10px;">
                        <p style="color: white; font-weight: bold;">Build Number: ${env.BUILD_NUMBER}</p>
                    </div>
                    <div style="background-color: #87CEEB; padding: 10px; margin-bottom: 10px;">
                        <p style="color: white; font-weight: bold;">URL: ${env.BUILD_URL}</p>
                    </div>
                </body>
                </html>
            """,
            to: 'didinpg8080@gmail.com',
            mimeType: 'text/html',
            attachmentsPattern: 'trivy.txt'
        }
    }
}
