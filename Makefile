# Makefile para empaquetar sshconfiggui como .deb, AppImage y Snap

APP_NAME      := sshconfiggui
VERSION       := 1.0.0
BIN_DIST      := dist/$(APP_NAME)
DEB_DIR       := build/$(APP_NAME)-$(VERSION)
APPIMAGE_DIR  := build/$(APP_NAME).AppDir
SNAP_NAME     := $(APP_NAME)_$(VERSION)_amd64

.PHONY: all clean build-bin build-deb build-snap

all: build-bin build-deb build-snap  # AppImage omitido en CI (requiere FUSE)

# 1. Generar binario con PyInstaller
build-bin:
	@echo "[1/4] Generando binario con PyInstaller..."
	pyinstaller --noconfirm --onefile --name $(APP_NAME) \
		--add-data "locales:locales" main.py

# 2. Crear paquete .deb
build-deb: build-bin
	@echo "[2/4] Construyendo paquete .deb..."
	rm -rf $(DEB_DIR)
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/lib/$(APP_NAME)
	mkdir -p $(DEB_DIR)/usr/bin
	mkdir -p $(DEB_DIR)/usr/share/applications

	# Archivo control
	echo "Package: $(APP_NAME)"                           >  $(DEB_DIR)/DEBIAN/control
	echo "Version: $(VERSION)"                          >> $(DEB_DIR)/DEBIAN/control
	echo "Section: utils"                               >> $(DEB_DIR)/DEBIAN/control
	echo "Priority: optional"                           >> $(DEB_DIR)/DEBIAN/control
	echo "Architecture: amd64"                          >> $(DEB_DIR)/DEBIAN/control
	echo "Depends: python3, python3-tk, gnupg2, pass"    >> $(DEB_DIR)/DEBIAN/control
	echo "Maintainer: Tu Nombre <tu@correo>"            >> $(DEB_DIR)/DEBIAN/control
	echo "Description: Gestor gráfico de ~/.ssh/config usando pass y GPG" >> $(DEB_DIR)/DEBIAN/control

	# Copiar binario y recursos
	cp $(BIN_DIST) $(DEB_DIR)/usr/lib/$(APP_NAME)/
	cp -r locales $(DEB_DIR)/usr/lib/$(APP_NAME)/

	# Script lanzador
	echo '#!/bin/sh'                                   >  $(DEB_DIR)/usr/bin/$(APP_NAME)
	echo 'exec /usr/lib/$(APP_NAME)/$(APP_NAME) "$$@"' >> $(DEB_DIR)/usr/bin/$(APP_NAME)
	chmod +x $(DEB_DIR)/usr/bin/$(APP_NAME)

	# Desktop entry
	echo "[Desktop Entry]"                                                 >  $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Type=Application"                                               >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Name=SSH Config GUI"                                            >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Exec=/usr/bin/$(APP_NAME)"                                      >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Icon=$(APP_NAME)"                                               >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Categories=Utility;Network;"                                    >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop
	echo "Terminal=false"                                                 >> $(DEB_DIR)/usr/share/applications/$(APP_NAME).desktop

	dpkg-deb --build $(DEB_DIR)
	@echo ".deb creado: $(DEB_DIR).deb"

# 4. Crear Snap
build-snap:
	@echo "[4/4] Construyendo Snap..."
	snapcraft --destructive-mode
	@echo "Snap generado: $(SNAP_NAME).snap"

# Limpiar artefactos
clean:
	rm -rf dist build __pycache__ *.spec
	rm -f *.snap *.deb
