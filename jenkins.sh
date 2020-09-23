#!/bin/bash
# Build distro images.

VERSION="$(cat VERSION)"
if [[ -z "$BRANCH" ]]; then
    BRANCH="$(git rev-parse --abbrev-ref HEAD | sed -e 's%/%-%g')"
fi

sed\
 -e "s/VERSION/${VERSION}/g"\
 -e "s/BRANCH/${BRANCH}/g"\
  artifactory.json > ../artifactory.json

dpkg-buildpackage -uc -us -tc
