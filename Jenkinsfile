pipeline {
    agent any

    environment {
        PROJECT_NAME = "Examen"
        SONARQUBE_URL = "http://sonarqube:9000"
        SONARQUBE_TOKEN = "sqa_b2152858c8eb361e87d72375849dfe0a986cdb86"
        TARGET_URL = "http://172.20.190.71:5000"
        // Definimos la ruta donde instalaremos ZAP
        ZAP_DIR = "/opt/zap"
    }

    stages {
        stage('Install Tools') {
            steps {
                sh '''
                    # Intentar arreglar instalaciones previas rotas
                    dpkg --configure -a || true
                    apt-get update
                    
                    # Instalamos python, entorno, doxygen, graphviz, wget y Java (para ZAP)
                    apt-get install -y --fix-missing python3 python3-venv python3-pip doxygen graphviz wget default-jre
                    
                    # Instalamos OWASP ZAP si no existe
                    if [ ! -d "$ZAP_DIR" ]; then
                        echo "Instalando OWASP ZAP..."
                        mkdir -p $ZAP_DIR
                        wget -qO- https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz | tar xvz -C $ZAP_DIR --strip-components=1
                    else
                        echo "ZAP ya está instalado."
                    fi
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
                                -Dsonar.exclusions=venv/**,docs/**,dependency-check-report/**,**/*.html,**/*.css,zap_report.html
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

        stage('Dynamic Security Audit (DAST)') {
            steps {
                sh '''
                    . venv/bin/activate
                    
                    # 1. Iniciar servidor Flask en background
                    echo "Iniciando servidor..."
                    nohup python3 vulnerable_server.py > /dev/null 2>&1 &
                    SERVER_PID=$!
                    
                    # 2. Esperar a que arranque
                    sleep 10
                    
                    # 3. Atacar con ZAP
                    echo "Atacando con ZAP..."
                    $ZAP_DIR/zap.sh -cmd -quickurl http://127.0.0.1:5000 -quickout $(pwd)/zap_report.html || true
                    
                    # 4. Matar servidor
                    echo "Apagando servidor..."
                    kill $SERVER_PID
                '''
            }
        }

        stage('Generate Documentation') {
            steps {
                sh '''
                    # Estrategia de lista blanca para Doxygen
                    FILES=$(find . -path "./venv" -prune -o -name "*.py" -print | tr '\n' ' ')
                    
                    echo "PROJECT_NAME      = 'Proyecto Vulnerable'" > Doxyfile.clean
                    echo "OUTPUT_DIRECTORY  = docs" >> Doxyfile.clean
                    echo "INPUT             = $FILES" >> Doxyfile.clean
                    echo "GENERATE_HTML     = YES" >> Doxyfile.clean
                    echo "HAVE_DOT          = YES" >> Doxyfile.clean
                    echo "EXTRACT_ALL       = YES" >> Doxyfile.clean
                    
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
                    reportDir: '.',
                    reportFiles: 'zap_report.html',
                    reportName: 'OWASP ZAP DAST Report'
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
