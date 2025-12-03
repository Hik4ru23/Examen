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
                    dpkg --configure -a || true
                    apt-get update
                    apt-get install -y --fix-missing python3 python3-venv python3-pip doxygen graphviz wget default-jre
                    
                    if [ ! -f "$ZAP_DIR/zap.sh" ]; then
                        echo "Instalando OWASP ZAP 2.15.0..."
                        rm -rf $ZAP_DIR
                        mkdir -p $ZAP_DIR
                        wget -O /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz
                        tar -xvzf /tmp/zap.tar.gz -C $ZAP_DIR --strip-components=1
                        chmod +x $ZAP_DIR/zap.sh
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
                    
                    # Debug: Verificar versión de Java (ZAP necesita Java 11+)
                    echo "Versión de Java:"
                    java -version
                    
                    echo "Iniciando servidor Flask..."
                    nohup python3 vulnerable_flask_app.py > flask.log 2>&1 &
                    SERVER_PID=$!
                    sleep 15
                    
                    # Verificar si Flask sigue vivo
                    if ! kill -0 $SERVER_PID > /dev/null 2>&1; then
                        echo "ERROR: El servidor Flask murió. Logs:"
                        cat flask.log
                        exit 1
                    fi
                    
                    echo "Atacando con ZAP..."
                    # EJECUCIÓN SIN SILENCIADOR DE ERRORES
                    # Usamos ruta explícita para el reporte
                    /opt/zap/zap.sh -cmd -quickurl http://127.0.0.1:5000 -quickout $(pwd)/zap_report.html
                    
                    # Verificación final
                    if [ -f "zap_report.html" ]; then
                        echo "EXITO: El reporte se generó correctamente."
                        ls -l zap_report.html
                    else
                        echo "ERROR: ZAP terminó pero NO generó el reporte."
                        exit 1
                    fi
                    
                    kill $SERVER_PID || true
                '''
            }
        }

        stage('Generate Documentation') {
            steps {
                sh '''
                    FILES=$(find . -path "./venv" -prune -o -name "*.py" -print | tr '\n' ' ')
                    echo "PROJECT_NAME      = 'Examen'" > Doxyfile.clean
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
