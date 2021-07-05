VERSION = 0.0-$(shell date +"%Y%m%d-%H%M")-$(shell git log -n 1 --pretty="format:%h")

deb:
	mkdir -p citen_$(VERSION)/usr/local/bin
	go build -o citen_$(VERSION)/usr/local/bin/citen .
	mkdir -p citen_$(VERSION)/lib/systemd/system
	cp citen.service citen_$(VERSION)/lib/systemd/system
	cp -r DEBIAN/ citen_$(VERSION)/
	sed -i 's/DEBVERSION/$(VERSION)/g' citen_$(VERSION)/DEBIAN/control
	dpkg-deb --build citen_$(VERSION) .
	rm -rf citen_$(VERSION)
