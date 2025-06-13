# https://github.com/cloudflare/flan

build: .docker_ready

.docker_ready: Dockerfile ./run.sh
	docker build --no-cache -t flan_scan -f Dockerfile .
	touch .docker_ready

container_name = flan_$(shell date +'%s')

last_tex_report = $(shell ls -t ./shared/reports/*.tex | head -1)
last_tex_report_basename = $(shell basename $(last_tex_report))

start: build
	docker run --rm --cap-drop=all --cap-add=NET_RAW --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" flan_scan | tee ./shared/run.log

pdf:
	cd ./shared/reports && pdflatex $(last_tex_report_basename)
	open $(last_tex_report:.tex=.pdf)

md: build
	docker run --rm --cap-drop=all --cap-add=NET_RAW --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" -e format=md flan_scan

html: build
	docker run --rm --cap-drop=all --cap-add=NET_RAW --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" -e format=html flan_scan

json: build
	docker run --rm --cap-drop=all --cap-add=NET_RAW --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" -e format=json flan_scan

# ===========================

fix_shared_permissions:
	sudo chmod -R a+rwx shared

clean:
	sudo rm -rf ./shared/xml_files/*
	sudo rm -rf ./shared/reports/*
	sudo rm -rf ./shared/run.log

# ===========================

check_ssh_changelog:
	@ mkdir -p ./shared/changelogs
	@ apt changelog openssh-server 2> /dev/null | tee ./shared/changelogs/openssh_$(shell sshd -V 2>&1 | cut -d"," -f1 | sed "s/OpenSSH//g" | sed "s/ Ubuntu//g")

check_patched_ssh_cves:
	@ apt changelog openssh-server 2> /dev/null | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}'

list_patched_ssh_cves:
	@ apt changelog openssh-server 2> /dev/null | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' | sort | uniq | tac

list_flanscan_cves:
	@ grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' ./shared/reports/$(last_tex_report) | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' | sort | uniq | tac

# ===========================

publish:
	docker run --name <container-name> \
		-v $(CURDIR)/shared:/shared \
		-e upload=gcp \
		-e bucket=<bucket-name> \
		-e GOOGLE_APPLICATION_CREDENTIALS=/shared/key.json
		-e format=<optional, one of: md, html or json> \
		flan_scan


#============================

test:
	@#docker run --rm --cap-drop=all --cap-add=NET_RAW --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" flan_scan mincvss=7.0 | tee ./shared/run.log
	nmap -sV -oX /shared/xml_files -oN - -v1 $@ --script=vulners/vulners.nse <ip-address>
