pipeline {
    agent any

    environment {
        PROJECT_NAME = "pipeline-test"
        SONARQUBE_URL = "http://sonarqube:9000"
        SONARQUBE_TOKEN = "sqa_b2152858c8eb361e87d72375849dfe0a986cdb86"
        TARGET_URL = "http://172.20.190.71:5000"
        // Definimos dónde se instalará ZAP
        ZAP_DIR = "/opt/zap"
    }

    stages {
        stage('Install Tools') {
            steps {
                sh '''
                    apt update
                    # Agregamos 'wget' (para bajar ZAP) y 'default-jre' (Java para correr ZAP)
                    apt install -y python3 python3-venv python3-pip doxygen graphviz wget default-jre
                    
                    # Instalación de OWASP ZAP si no existe
                    if [ ! -d "$ZAP_DIR" ]; then
                        echo "Instalando OWASP ZAP..."
                        mkdir -p $ZAP_DIR
                        # Descargamos la versión 2.14.0 (Linux)
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

        stage('Static Security Audit (SAST)') {
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

        // --- NUEVA ETAPA: ANÁLISIS DINÁMICO CON ZAP ---
        stage('Dynamic Security Audit (DAST)') {
            steps {
                sh '''
                    . venv/bin/activate
                    
                    # 1. Levantar la aplicación en segundo plano (background)
                    echo "Iniciando servidor Flask..."
                    # nohup permite que el proceso siga vivo aunque el script termine momentáneamente
                    nohup python3 vulnerable_server.py > /dev/null 2>&1 &
                    
                    # Guardamos el ID del proceso (PID) para matarlo al terminar
                    SERVER_PID=$!
                    echo "Servidor iniciado con PID: $SERVER_PID"
                    
                    # Esperamos 10 segundos para asegurar que Flask arrancó bien
                    sleep 10
                    
                    # 2. Ejecutar OWASP ZAP (Quick Scan)
                    # -cmd: Modo consola (sin interfaz gráfica)
                    # -quickurl: La URL a atacar
                    # -quickout: Dónde guardar el reporte HTML
                    echo "Iniciando ataque con ZAP..."
                    $ZAP_DIR/zap.sh -cmd -quickurl http://127.0.0.1:5000 -quickout $(pwd)/zap_report.html || true
                    
                    # 3. Apagar la aplicación limpiamente
                    echo "Apagando servidor..."
                    kill $SERVER_PID
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
                // Publicar Reporte OWASP Dependency Check
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'dependency-check-report',
                    reportFiles: 'dependency-check-report.html',
                    reportName: 'OWASP Dependency Check Report'
                ])

                // Publicar Reporte OWASP ZAP (NUEVO)
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'zap_report.html',
                    reportName: 'OWASP ZAP DAST Report'
                ])

                // Publicar Documentación Doxygen
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
