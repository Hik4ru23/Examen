pipeline {
    agent any

    environment {
        PROJECT_NAME = "Examen"
        SONARQUBE_URL = "http://sonarqube:9000"
        SONARQUBE_TOKEN = "sqa_b2152858c8eb361e87d72375849dfe0a986cdb86"
        TARGET_URL = "http://172.20.190.71:5000"
        ZAP_DIR = "/opt/zap"
    }

    stages {
        stage('Install Tools') {
            steps {
                sh '''
                    # Reparar e instalar dependencias
                    dpkg --configure -a || true
                    apt-get update
                    apt-get install -y --fix-missing python3 python3-venv python3-pip doxygen graphviz wget default-jre
                    
                    # Instalación de ZAP (Versión Robustecida)
                    if [ ! -f "$ZAP_DIR/zap.sh" ]; then
                        echo "Instalando OWASP ZAP..."
                        rm -rf $ZAP_DIR
                        mkdir -p $ZAP_DIR
                        
                        # Descargar y descomprimir
                        wget -qO /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
                        tar -xvzf /tmp/zap.tar.gz -C $ZAP_DIR --strip-components=1
                        
                        # Dar permisos de ejecución
                        chmod +x $ZAP_DIR/zap.sh
                    else
                        echo "ZAP ya está instalado correctamente."
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
                    echo "Iniciando servidor Flask..."
                    # Usamos python3 explícitamente y redirigimos salida
                    nohup python3 vulnerable_server.py > flask.log 2>&1 &
                    SERVER_PID=$!
                    echo "Servidor iniciado con PID: $SERVER_PID"
                    
                    # 2. Esperar a que arranque
                    sleep 15
                    
                    # Verificar si el servidor sigue vivo (si murió, mostrar log)
                    if ! kill -0 $SERVER_PID > /dev/null 2>&1; then
                        echo "ERROR: El servidor Flask murió inmediatamente. Logs:"
                        cat flask.log
                        exit 1
                    fi
                    
                    # 3. Atacar con ZAP
                    echo "Ejecutando ZAP..."
                    if [ -f "$ZAP_DIR/zap.sh" ]; then
                        $ZAP_DIR/zap.sh -cmd -quickurl http://127.0.0.1:5000 -quickout $(pwd)/zap_report.html || true
                    else
                        echo "ERROR CRÍTICO: No encuentro zap.sh en $ZAP_DIR"
                        ls -R $ZAP_DIR
                        exit 1
                    fi
                    
                    # 4. Matar servidor
                    echo "Apagando servidor..."
                    kill $SERVER_PID || true
                '''
            }
        }

        stage('Generate Documentation') {
            steps {
                sh '''
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
