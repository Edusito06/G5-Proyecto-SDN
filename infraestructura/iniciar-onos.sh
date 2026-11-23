set -eu
umask 077
export ANSIBLE_LOG_PATH="$PWD/ansible-ejecucion.log"
mkdir -p evidencia
touch "$ANSIBLE_LOG_PATH"
ln -f "$ANSIBLE_LOG_PATH" evidencia/ansible-ejecucion.log
if ! command -v ansible-playbook >/dev/null || ! command -v sshpass >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y ansible-core sshpass
fi
export ANSIBLE_SSH_COMMON_ARGS='-o StrictHostKeyChecking=accept-new'
case "$1" in
  ONOS) set -- onos.yml ;;
  Articulo) set -- onos.yml paper.yml evidencia-arbol.yml ;;
  Evidencia) set -- evidencia-arbol.yml ;;
  Evento) set -- evento-puerto.yml ;;
  Proteccion) set -- proteccion.yml ;;
esac
for play do
  ansible-playbook -i inventario.yml --syntax-check "$play" -e @puertos-ejemplo.yml
done
echo 'SSH password: clave de ubuntu de las VMs.'
echo 'BECOME password: clave sudo de ubuntu de las VMs. Si coincide con SSH, pulsa Enter.'
echo 'La clave REST de ONOS se solicita aparte.'
ansible-playbook -i inventario.yml -e @puertos-ejemplo.yml -k -K "$@"