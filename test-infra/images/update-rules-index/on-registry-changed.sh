#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The KhulnaSoft Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GH_PROXY="${GH_PROXY:-"http://ghproxy"}"
GH_ORG="${GH_ORG:-"khulnasoft"}"
GH_REPO="${GH_REPO:-"rules"}"
GH_INDEX_REPO="${GH_INDEX_REPO:-"fanalctl"}"
GH_INDEX_REPO_BRANCH="${GH_INDEX_REPO_BRANCH:-"gh-pages"}"
BOT_NAME="${BOT_NAME:-"poiana"}"
BOT_MAIL="${BOT_MAIL:-"51138685+poiana@users.noreply.github.com"}"
BOT_GPG_KEY_PATH="${BOT_GPG_KEY_PATH:-"/root/gpg-signing-key/poiana.asc"}"
BOT_GPG_PUBLIC_KEY="${BOT_GPG_PUBLIC_KEY:-"EC9875C7B990D55F3B44D6E45F284448FF941C8F"}"

export GIT_COMMITTER_NAME=${BOT_NAME}
export GIT_COMMITTER_EMAIL=${BOT_MAIL}
export GIT_AUTHOR_NAME=${BOT_NAME}
export GIT_AUTHOR_EMAIL=${BOT_MAIL}

# env variables needed to update index.
export REGISTRY_USER=$GH_ORG
export REGISTRY="ghcr.io"
export OCI_REPO_PREFIX="$REGISTRY/$REGISTRY_USER/$GH_REPO"

# Sets git user configs, otherwise errors out.
# $1: git user name
# $2: git user email
ensure_git_config() {
    echo "> configuring git user (name=$1, email=$2)..." >&2
    git config --global user.name "$1"
    git config --global user.email "$2"

    git config user.name &>/dev/null && git config user.email &>/dev/null && return 0
    echo "ERROR: git config user.name, user.email unset. No defaults provided" >&2
    return 1
}

# Configures GPG key, otherwise errors out.
# $1: GPG key location
# $2: GPG ASCII armored public key
ensure_gpg_key() {
    echo "> configuring git with gpg key=$1..." >&2
    gpg --import "$1"
    git config --global commit.gpgsign true
    git config --global user.signingkey "$2"

    git config --global commit.gpgsign &>/dev/null && git config --global user.signingkey &>/dev/null && return 0
    echo "ERROR: git gpg key location, public key ID unset. No defaults provided" >&2
    return 1
}

# $1: path of the file containing the token
get_user_from_token() {
    curl --silent -H "Authorization: token $(cat "$1")" "https://api.github.com/user" | grep -Po '"login": "\K.*?(?=")'
}

# $1: temporary path to clone the repo
clone_index_repo() {
    echo "> cloning distribution index repository (https://github.com/${GH_ORG}/${GH_INDEX_REPO}.git)..." >&2
    mkdir -p "$1"
    pushd "$1"
    git clone "https://github.com/${GH_ORG}/${GH_INDEX_REPO}.git"
    pushd "${GH_INDEX_REPO}"
    echo "> checkout ${GH_INDEX_REPO_BRANCH} branch..." >&2
    git checkout ${GH_INDEX_REPO_BRANCH}
    popd
    popd
}

# $1: path of the file containing the token
# $2: path to the local working copy of the index repo
push_index() {
    echo "> pushing distribution index..." >&2
    pushd "$2"

    git add index.yaml
    git commit --message="update(index.yaml): new rules registry data" --signoff

    # N.B., no force push here. 
    # If other jobs modify the index and a git conflict occurs, 
    # better to fail instead of overwriting their changes.
    user=$(get_user_from_token "$1")
    git push \
        "https://${user}:$(cat "$1")@github.com/${GH_ORG}/${GH_INDEX_REPO}" \
        "HEAD:${GH_INDEX_REPO_BRANCH}"

    popd
}

# $1: the program to check
function check_program {
    if hash "$1" 2>/dev/null; then
        type -P "$1" >&/dev/null
    else
        echo "> aborting because $1 is required..." >&2
       return 1
    fi
}

# Meant to be run in the https://github.com/khulnasoft/rules repository.
# $1: path of the file containing the token
main() {
    # Checks
    check_program "gpg"
    check_program "git"
    check_program "curl"
    check_program "pr-creator"
    check_program "awk"

    # Settings
    ensure_git_config "${BOT_NAME}" "${BOT_MAIL}"
    ensure_gpg_key "${BOT_GPG_KEY_PATH}" "${BOT_GPG_PUBLIC_KEY}"
    
    # Clone the index repo and checkout to the correct branch
    clone_index_repo "/tmp"

    pushd build/registry

    go build -o rules-registry ./...

    popd

    build/registry/rules-registry update-index registry.yaml /tmp/${GH_INDEX_REPO}/index.yaml

    # Finally, commit and push the index
    push_index "$1" "/tmp/${GH_INDEX_REPO}"

}

if [[ $# -lt 1 ]]; then
    echo "Usage: $(basename "$0") <path to github token>" >&2
    exit 1
fi

main "$@"
