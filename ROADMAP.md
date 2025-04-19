# 🗺️ Roadmap – sshConfigGUI

## ✅ Fase 1 – Base funcional
- [x] Visualización de entradas de `~/.ssh/config`
- [x] Añadir, editar y eliminar hosts
- [x] Guardado automático con backup `.bak`
- [x] Interfaz funcional en Tkinter

## ✅ Fase 2 – UX/UI
- [x] Scroll para lista de hosts
- [x] Orden alfabético
- [x] Confirmación al eliminar
- [x] Botón “Restaurar desde backup”
- [x] Indicador visual de guardado

## ✅ Fase 3 – Campos avanzados
- [x] Soporte para ProxyJump, Forwarding, ServerAlive...
- [x] Validación de IP/puertos
- [x] Múltiples IdentityFile

## ✅ Fase 4 – Seguridad
- [x] Protección con contraseña maestra
- [x] Instalación automática de GPG y Pass
- [x] Generación automática de clave GPG
- [x] Almacenamiento de contraseña en `pass`
- [x] Ocultar/mostrar campos sensibles (`IdentityFile`, `Password`)
- [x] Integración total con `pass` para campos como `Password`

## 🧪 Fase 5 – Utilidades extra
- [x] Búsqueda de hosts por nombre
- [x] Copiar entrada SSH al portapapeles
- [x] Selector de archivo para IdentityFile
- [x] Recordar tamaño de ventana, último host seleccionado, visibilidad de contraseña
- [x] Modo solo lectura para evitar ediciones accidentales
- [x] Detección de duplicados al guardar
- [ ] Recarga automática si se modifica ~/.ssh/config externamente
- [x] Test de conexión SSH
- [x] Exportar/importar JSON (descartado YAML)
- [x] Backups con timestamp en carpeta separada

## 📦 Fase 6 – Empaquetado
- [ ] `.deb` instalable
- [ ] AppImage / `.exe`
- [ ] README con screenshots

## 🌐 Fase 7 – Comunidad y multiplataforma
- [ ] Soporte para Windows/macOS
- [ ] Traducción (ES/EN)
- [ ] Activar Issues y Discussions
- [ ] Sitio web del proyecto
