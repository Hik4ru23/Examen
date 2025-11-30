pipeline {
    agent any

    environment {
        PROJECT_NAME = "pipeline-test"
        SONARQUBE_URL = "http://sonarqube:9000"
        SONARQUBE_TOKEN = "sqa_b2152858c8eb361e87d72375849dfe0a986cdb86"
        TARGET_URL = "http://172.20.190.71:5000"
    }

    stages {
        stage('Install Tools') {
            steps {
                sh '''
                    apt update
                    apt install -y python3 python3-venv python3-pip doxygen graphviz
                '''
            }
        }
        
        stage('Setup Environment') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Python Security Audit') {
            steps {
                sh '''
                    . venv/bin/activate
                    pip install pip-audit
                    mkdir -p dependency-check-report
                    pip-audit -r requirements.txt -f markdown -o dependency-check-report/pip-audit.md || true
                '''
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarQubeScanner'
                    withSonarQubeEnv('SonarQubeScanner') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                                -Dsonar.projectKey=$PROJECT_NAME \
                                -Dsonar.sources=. \
                                -Dsonar.host.url=$SONARQUBE_URL \
                                -Dsonar.login=$SONARQUBE_TOKEN \
                                -Dsonar.exclusions=venv/**,docs/**,dependency-check-report/**,**/*.html,**/*.css
                        """
                    }
                }
            }
        }

        stage('Dependency Check') {
            environment {
                NVD_API_KEY = credentials('nvdApiKey')
            }
            steps {
                dependencyCheck additionalArguments: "--scan . --format HTML --out dependency-check-report --enableExperimental --enableRetired --nvdApiKey ${NVD_API_KEY} --disableOssIndex --disableAssembly", odcInstallation: 'DependencyCheck'
            }
        }

        stage('Generate Documentation') {
            steps {
                // ESTRATEGIA INFALIBLE: Whitelist (Lista blanca)
                // 1. Buscamos solo los archivos .py, ignorando la carpeta venv
                // 2. Pasamos esa lista exacta a Doxygen. Así NO puede mirar donde no debe.
                sh '''
                    # Encuentra archivos .py, pero PODA (prune) la carpeta venv para no entrar ahí
                    FILES=$(find . -path "./venv" -prune -o -name "*.py" -print | tr '\n' ' ')
                    
                    echo "PROJECT_NAME      = 'Proyecto Vulnerable'" > Doxyfile.clean
                    echo "OUTPUT_DIRECTORY  = docs" >> Doxyfile.clean
                    
                    # Aquí está el truco: INPUT solo contiene tus archivos de código reales
                    echo "INPUT             = $FILES" >> Doxyfile.clean
                    
                    echo "GENERATE_HTML     = YES" >> Doxyfile.clean
                    echo "HAVE_DOT          = YES" >> Doxyfile.clean
                    echo "EXTRACT_ALL       = YES" >> Doxyfile.clean
                    
                    echo "--- Archivos a documentar ---"
                    echo $FILES
                    echo "---------------------------"
                    
                    doxygen Doxyfile.clean
                '''
            }
        }

        stage('Publish Reports') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'dependency-check-report',
                    reportFiles: 'dependency-check-report.html',
                    reportName: 'OWASP Dependency Check Report'
                ])

                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'docs/html',
                    reportFiles: 'index.html',
                    reportName: 'Doxygen Documentation',
                    reportTitles: 'Doxygen'
                ])
            }
        }
    }
}
