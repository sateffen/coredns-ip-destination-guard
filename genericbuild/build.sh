#!/usr/bin/env bash

# Configure the version to use here.
corednsVersion=1.14.0

###############################################################################################
# Below this is the actual build. Don't change anything, if you don't know what you are doing #
###############################################################################################

# Make sure we're in this directory, and not somewhere else
cd $(dirname -- "${BASH_SOURCE[0]}")
buildDir=src
mkdir $buildDir

# Then set some variables we'll use for building
currentPath=$(pwd)
tmpGoPath=${buildDir}/build
corednsFolder=${buildDir}/coredns-${corednsVersion}
corednsTmpFile=coredns-${corednsVersion}.tar.gz

curl -L -o $corednsTmpFile https://github.com/coredns/coredns/archive/refs/tags/v${corednsVersion}.tar.gz
tar -xzf $corednsTmpFile -C $buildDir

# Move the plugin config for coredns to the repo, so we build a coredns instance we want
cp plugin.cfg ${corednsFolder}/plugin.cfg

export GOPATH=$(realpath $tmpGoPath)
export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"

# Actually execute the build and move the resulting file up for us
cd $corednsFolder
make coredns
cd $currentPath
mv "${corednsFolder}/coredns" coredns-ip-destination-guard
