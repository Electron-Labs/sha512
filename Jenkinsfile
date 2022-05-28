pipeline {
  agent any
  stages {
    stage('TestStage') {
      steps {
        sh '''dir=`echo $JOB_NAME | sed \'s/\\//_/g\'`
cd /var/lib/jenkins/workspace/$dir
docker build -t sha512 . 
docker rmi sha512:latest
echo "Tested Successfully"
'''
      }
    }

  }
}