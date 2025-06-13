#!/bin/bash

current_time=$(date "+%Y.%m.%d-%H.%M")
if [[ -z $upload ]]
then
    root_dir=/shared/
else
    root_dir=/
    mkdir -p /xml_files
    mkdir -p /reports
fi

report_extension="tex"

if [[ ! -z ${format} ]]
then
    report_extension=${format}
fi

xml_dir=xml_files/${current_time}
report_file=reports/report_${current_time}.${report_extension}

upload() {
    if [[ -z $upload ]]
    then
        return
    elif [ $upload = "aws" ]
    then
        python /aws_push.py $1
    elif [ $upload = "gcp" ]
    then
        python /gcp_push.py $1
    fi
}

get_filename(){
    echo $1 | tr / -
}

filter_out_ubuntu_cvss(){

    xmlfile="$1"
    xmlfile_orig="${xmlfile}.orig"

    # Backup generated XML for comparison...
    cp ${xmlfile} ${xmlfile_orig}

    if grep -qi "Ubuntu" ${xmlfile}; then

        mkdir -p ${root_dir}/changelogs

        openssh_version=$(xmlstarlet sel -t -v '//port/service[@name="ssh"]/@version' "${xmlfile}" | sed "s/ Ubuntu /-/g")
        wget -q -O /shared/changelogs/openssh_${openssh_version} "https://changelogs.ubuntu.com/changelogs/pool/main/o/openssh/openssh_${openssh_version}/changelog"

        patched_cvss=($(cat /shared/changelogs/openssh_${openssh_version} | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' | sort | uniq | tac))
        cvss_found=($(grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' ${xmlfile} | grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,7\}' | sort | uniq | tac))

        echo
        echo "Verifying Ubuntu patches:"
        for cve in ${cvss_found[@]}; do
            echo -ne "- Checking ${cve}... \t"
            if [[ " ${patched_cvss[*]} " == *" ${cve} "* ]]; then
                echo "Already patched, filtering it out."
                xmlstarlet ed -d "//table[elem[@key='id']='${cve}']" ${xmlfile} > /dev/null 2>&1
            else
                echo "Not fixed yet."
            fi
        done
        echo
    fi
}

mkdir -p ${root_dir}${xml_dir}
while IFS= read -r line
do
  current_time=$(date "+%Y.%m.%d-%H.%M.%S")
  filename=$(get_filename $line)".xml"
  nmap -sV -oX ${root_dir}${xml_dir}/${filename} -oN - -v1 $@ --script=vulners/vulners.nse ${line}
  filter_out_ubuntu_cvss ${root_dir}${xml_dir}/${filename}
  upload ${xml_dir}/${filename}
done < /shared/ips.txt

python /output_report.py ${root_dir}${xml_dir} ${root_dir}${report_file} /shared/ips.txt
if [[ ${report_extension} = "tex" ]]
then
    sed -i 's/_/\\_/g' ${root_dir}${report_file}
    sed -i 's/\$/\\\$/g' ${root_dir}${report_file}
    sed -i 's/#/\\#/g' ${root_dir}${report_file}
    sed -i 's/%/\\%/g' ${root_dir}${report_file}
fi
upload ${report_file}
