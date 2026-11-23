param([ValidateSet('ONOS','Articulo')][string]$Perfil = 'ONOS')
$ErrorActionPreference = 'Stop'
$gateway = 'ubuntu@10.20.12.7'
$remote = 'bootstrap-g05-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
Write-Host "Copiando los playbooks al gateway en ~/$remote"
& scp.exe -r $PSScriptRoot "${gateway}:$remote"
if ($LASTEXITCODE) { throw 'Error al copiar por SSH al gateway.' }
$run = @'
set -eu
umask 077
export ANSIBLE_LOG_PATH="$PWD/ansible-ejecucion.log"
if ! command -v ansible-playbook >/dev/null || ! command -v sshpass >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y ansible-core sshpass
fi
export ANSIBLE_SSH_COMMON_ARGS='-o StrictHostKeyChecking=accept-new'
if [ "$1" = Articulo ]; then
  ansible-playbook -i inventario.yml --syntax-check paper.yml
  if [ ! -s paper-app/target/g05-inband-1.0.0.oar ]; then
    echo 'Falta el OAR en paper-app/target. Compila paper-app con Maven y transfiere el paquete antes de ejecutar el perfil.'
    exit 1
  fi
fi
ansible-playbook -i inventario.yml --syntax-check onos.yml
ansible-playbook -i inventario.yml onos.yml -k -K
if [ "$1" = Articulo ]; then
  ansible-playbook -i inventario.yml paper.yml -e @puertos-ejemplo.yml -k -K
fi
'@
$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($run.Replace("`r",'')))
& ssh.exe -t $gateway "cd '$remote' && printf %s '$payload' | base64 -d > iniciar-onos.sh && bash iniciar-onos.sh $Perfil"
if ($LASTEXITCODE) { throw "Arranque pendiente. Registro en el gateway: ~/$remote/ansible-ejecucion.log" }
