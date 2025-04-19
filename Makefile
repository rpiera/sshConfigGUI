# Makefile para automatizar la creación de los paquetes .deb, AppImage y Snap

# Variables
APP_NAME      := sshconfiggui
VERSION       := 1.0.0
BIN_DIST      := dist/$(APP_NAME)
DEB_DIR       := build/$(APP_NAME)-$(VERSION)
APPIMAGE_DIR  := build/$(APP_NAME).AppDir
SNAP_NAME     := $(APP_NAME)_$(VERSION)_amd64

.PHONY: all clean build-bin build-deb build-appimage build-snap

all: build-bin build-deb build-appimage build-snap

# 1. Generar ejecutable via PyInstaller
build-bin:
	@echo "[1/4] Generando binario con PyInstaller..."
	pyinstaller --noconfirm --onefile --name $(APP_NAME) \
		--add-data "locales:locales" main.py

# 2. Empaquetar .deb
build-deb: build-bin
	@echo "[2/4] Construyendo paquete .deb..."
	rm -rf $(DEB_DIR)
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/lib/$(APP_NAME)
	mkdir -p $(DEB_DIR)/usr/bin
	mkdir -p $(DEB_DIR)/usr/share/applications

	# Control
	cat > $(DEB_DIR)/DEBIAN/control << EOF
Package: $(APP_NAME)
Version: $(VERSION)
Section: utils
Priority: optional
Architecture: amd64
Depends: python3, python3-tk, gnupg2, pass
Maintainer: Tu Nombre <tu@correo>
Description: Gestor gráfico de ~/.ssh/config usando pass y GPG
EOF

	# Copiar binario y recursos
	cp $(BIN_DIST) $(DEB_DIR)/usr/lib/$(APP_NAME)/
	cp -r locales $(DEB_DIR)/usr/lib/$(APP_NAME)/
	# Lanzador
	cat > $(DEB_DIR)/usr/bin/$(APP_NAME) << 'EOF'
#!/bin/sh
exec /usr/lib/$(APP_NAME)/$(APP_NAME) "$@"
EOF
	chmod +x $(DEB_DIR)/usr/bin/$(APP_NAME)
	# Desktop entry (opcional)
	cp resources/sshconfiggui.desktop $(DEB_DIR)/usr/share/applications/

	dpkg-deb --build $(DEB_DIR)
	@echo ".deb creado: $(DEB_DIR).deb"

# 3. Empaquetar AppImage
build-appimage: build-bin
	@echo "[3/4] Construyendo AppImage..."
	rm -rf $(APPIMAGE_DIR)
	mkdir -p $(APPIMAGE_DIR)/usr/bin
	mkdir -p $(APPIMAGE_DIR)/usr/lib/$(APP_NAME)
	mkdir -p $(APPIMAGE_DIR)/usr/share/applications
	mkdir -p $(APPIMAGE_DIR)/usr/share/icons/hicolor/128x128/apps

	# Copiar binario y recursos
	cp $(BIN_DIST) $(APPIMAGE_DIR)/usr/bin/$(APP_NAME)
	cp -r locales $(APPIMAGE_DIR)/usr/lib/$(APP_NAME)/
	cp resources/sshconfiggui.png $(APPIMAGE_DIR)/usr/share/icons/hicolor/128x128/apps/$(APP_NAME).png
	cp resources/sshconfiggui.desktop $(APPIMAGE_DIR)/usr/share/applications/

	# AppRun
	cat > $(APPIMAGE_DIR)/AppRun << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/bin:$PATH"
exec $(APP_NAME) "$@"
EOF
	chmod +x $(APPIMAGE_DIR)/AppRun

	# Crear AppImage
	appimagetool $(APPIMAGE_DIR)
	@echo "AppImage generado."

# 4. Empaquetar Snap
build-snap:
	@echo "[4/4] Construyendo Snap..."
	snapcraft --destructive-mode --output=$(SNAP_NAME).snap
	@echo "Snap generado: $(SNAP_NAME).snap"

# Limpiar artefactos
clean:
	rm -rf dist build __pycache__ *.spec
	rm -f *.snap *.deb
