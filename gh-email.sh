#!/usr/bin/env bash

# Default values
GH_TIMEOUT=10
USE_FILTERS='true'
INCLUDE_NAME='true'
INCLUDE_FORK='false'
UPDATE='false'
KEEP_DOWNLOADS='false'
GH_HOST="${GH_HOST:-github.com}"
GH_TOKEN="${GH_TOKEN:-${GH_ENTERPRISE_TOKEN:-}}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD_WHITE='\033[1;37m'
NO_COLOR='\033[0m'

set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes

usage() {
	echo -e "\nUsage: ${0} [OPTIONS] [repo url|local repo|GitHub Org/User]"
	echo -e '\nOptions:'
	echo -e '\t-h, --help\t\tPrint this help page'
	echo -e '\t-o, --output=FILE\tOutput as a CSV file'
	echo -e '\t-i, --input=FILE\tFile to read the list of targets from'
	echo -e '\t-f, --filter=FILTER\tFilter out emails containing this filter'
	echo -e '\t-r, --raw\t\tNo filter no banner'
	echo -e '\t--fork\t\t\tInclude forked repos in the scan'
	echo -e '\t--no-name\t\tExclude authors'\''s name'
	echo -e '\t-k, --keep\t\tKeep downloaded .git(s) after the scan'
	echo -e '\t-u, --update\t\tUpdate existing .git(s) before the scan'
	echo -e '\t--no-color\t\tDo not use colors\n'
}

echo_info() {
	echo -e "[${BLUE}i${NO_COLOR}] - ${BLUE}${*}${NO_COLOR}"
}

echo_error() {
	echo -e "[${RED}-${NO_COLOR}] - ${RED}Error: ${*}${NO_COLOR}"
}

parse_args() {
	read -r SCAN_NAME USER_FILTERS OUTPUT_FILE INPUT_FILE TARGET <<<''
	while (("$#")); do
		case "${1}" in
		--help | -h)
			usage
			exit
			;;
		--output=*) OUTPUT_FILE="${1#*=}" ;;
		--output | -o)
			if [ -n "${OUTPUT_FILE}" ]; then
				echo_error 'output file already set'
				exit 1
			else
				OUTPUT_FILE="${2}"
				shift
			fi
			;;
		--input=*) INPUT_FILE="${1#*=}" ;;
		--input | -i)
			if [ -n "${INPUT_FILE}" ]; then
				echo_error 'input file already set'
				exit 1
			elif [ -n "${TARGET}" ]; then
				echo_error 'target already set'
				exit 1
			else
				INPUT_FILE="${2}"
				shift
			fi
			;;
		--filter=*) [ -n "${1#*=}" ] && USER_FILTERS+=" -e ${1#*=}" ;;
		--filter | -f)
			[ -n "${2}" ] && USER_FILTERS+=" -e ${2}"
			shift
			;;
		--raw | -r) USE_FILTERS='false' ;;
		--fork) INCLUDE_FORK='true' ;;
		--no-name) INCLUDE_NAME='false' ;;
		--keep | -k) KEEP_DOWNLOADS='true' ;;
		--update | -u) UPDATE='true' ;;
		--no-color) read -r GREEN RED BLUE YELLOW BOLD_WHITE NO_COLOR <<<'' ;;
		--*)
			echo_error "unknown argument: ${1}"
			usage
			exit 1
			;;
		*)
			if [ -n "${TARGET}" ]; then
				echo_error 'use input file to scan multiple targets'
				usage
				exit 1
			else
				TARGET="${1}"
			fi
			;;
		esac
		shift
	done

	check_requirements

	if [ -n "${TARGET}" ]; then
		if [ -n "${INPUT_FILE}" ]; then
			parse_input_file "${INPUT_FILE}"

			# If target is not in the input file
			if ! grep --quiet --max-count 1 "${TARGET}" <<<"${REPO_LIST}"; then
				local repo_list scan_name
				repo_list="${REPO_LIST}"
				scan_name="${SCAN_NAME}"

				# Add target to the list
				target_to_repo_list "${TARGET}"
				REPO_LIST+="${repo_list}"
				SCAN_NAME="${scan_name}, ${SCAN_NAME}"
			fi
		else
			if ! target_to_repo_list "${TARGET}"; then
				exit 1
			fi
		fi
	elif [ -n "${INPUT_FILE}" ]; then
		parse_input_file "${INPUT_FILE}"
	else
		usage
		exit
	fi
}

# Output: ${USE_GH_CLI}
check_requirements() {
	USE_GH_CLI='false'
	if ! command -v git >/dev/null 2>/dev/null; then
		echo_error 'Requirements: git not found'
		usage
		exit 1
	elif command -v gh >/dev/null 2>/dev/null; then
		if timeout "${GH_TIMEOUT}" gh auth status --hostname 'github.com' >/dev/null 2>/dev/null; then
			USE_GH_CLI='true'
		else
			echo_info 'GH CLI is not authenticated, API rate limit may apply'
		fi
	fi

	if ! command -v curl >/dev/null 2>/dev/null; then
		echo_error 'Requirements: curl not found'
		usage
		exit 1
	fi
}

# Usage: target_to_repo_list TARGET
# Output: ${REPO_LIST}
target_to_repo_list() {
	local target ret_error scan_name
	target="${1}"
	ret_error=1

	# Get ${REPO_PATH}
	uri_to_path "${target}"

	# Check if target path is a local dir
	if [ -d "${target}" ]; then
		SCAN_NAME="$(basename "${target}")"
		get_repo_list_local "${target}"
		ret_error=0

	# Check if target URI is a local dir
	elif is_path "${REPO_PATH}" && [ -d "${REPO_PATH}" ]; then
		SCAN_NAME="${REPO_PATH}"
		get_repo_list_local "${REPO_PATH}"
		ret_error=0

	# Check if target is a remote git repo
	elif repo_exist_not_empty "${target}"; then
		if is_path "${REPO_PATH}"; then
			SCAN_NAME="${REPO_PATH}"
		else
			scan_name="${target#*.*/}"
			SCAN_NAME="${scan_name%.git}"
		fi
		REPO_LIST="${target}"
		ret_error=0

	# Check if path is a GitHub repo
	elif is_path "${target}"; then
		path_to_uri "${target}"
		if repo_exist_not_empty "${REPO_URI}"; then
			SCAN_NAME="${target}"
			REPO_LIST="${REPO_URI}"
			ret_error=0
		else
			echo_error 'repository empty or nonexistent'
		fi

	# Otherwise check if target is a GitHub Org/User
	elif gh_owner_exist "${target}"; then
		if gh_owner_has_repo "${target}"; then
			SCAN_NAME="${target}"
			get_gh_owner_repo_list "${target}"
			if [ -z "${REPO_LIST}" ] && [ "${INCLUDE_FORK}" = 'false' ]; then
				echo_error 'owner has no accessible repository matching criterias'
			else
				ret_error=0
			fi
		else
			echo_error 'owner has no accessible repository'
		fi
	fi

	if [ -z "${REPO_LIST}" ]; then
		echo_error "target not found or empty: ${target}"
	else
		REPO_LIST="$(uniq <<<"${REPO_LIST}")"
	fi

	return "${ret_error}"
}

# Usage: parse_input_file FILE
# Output: ${REPO_LIST}
parse_input_file() {
	local input_file initial_repo_list final_repo_list line
	input_file="${1}"
	final_repo_list=''

	initial_repo_list="$(sed -e 's:#.*$::g' -e '/^[[:space:]]*$/d' "${input_file}" | awk '!seen[$0]++')"
	if [ -s "${input_file}" ]; then
		while IFS='' read -r line; do
			if [ -n "${line}" ]; then
				target_to_repo_list "${line}"
				#final_repo_list+="${REPO_LIST}"$'\n'
				final_repo_list="$(echo -e "${final_repo_list}\n${REPO_LIST}")"
			fi
		done <<<"${initial_repo_list}"
		SCAN_NAME=''
	else
		echo_error "file not found or empty: ${input_file}"
		exit 1
	fi

	# Set output ${REPO_LIST} and filter duplicates
	if [ -n "${final_repo_list}" ]; then
		REPO_LIST="$(awk '!seen[$0]++' <<<"${final_repo_list}")"
	else
		exit 1
	fi
}

clean() {
	if [ "${KEEP_DOWNLOADS}" = 'false' ]; then
		rm -rf "${TEMP_DIR:?}\n"
	fi
}

on_error() {
	local result=$?
	clean
	exit "${result}"
}

# Usage: repo_exist_not_empty <repo_url>
repo_exist_not_empty() {
	local repo_url
	repo_url="${1}"
	git ls-remote --quiet --exit-code --heads "${repo_url}" >/dev/null 2>&1
}

# Usage: uri_to_path <repo_uri>
# Output: ${REPO_PATH}
uri_to_path() {
	local repo_uri
	repo_uri="${1}"
	REPO_PATH="$(awk '{
		gsub(/\/+$/, "", $0); sub(/[?#].*$/, "", $0); sub(/.*@/, "", $0); sub(/.*:/, "", $0)
		match($0, /[^\/]+\/[^\/]+(\.git)?$/)
		repo = substr($0, RSTART, RLENGTH)
		sub(/\.git$/, "", repo)
		print repo
	}' <<<"${repo_uri}")"
}

# Usage: path_to_uri <repo_path>
# Output: ${REPO_URI}
path_to_uri() {
	local repo_path
	repo_path="${1}"
	REPO_URI="https://${GH_TOKEN:+${GH_TOKEN}@}${GH_HOST}/${repo_path}"
}

# Usage: is_path <repo_path>
is_path() {
	local repo_path
	repo_path="${1}"
	[[ "${repo_path}" =~ ^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$ ]]
}

# Usage: gh_owner_exist <owner>
gh_owner_exist() {
	local owner http_code
	owner="${1}"

	if [ "${USE_GH_CLI}" = 'true' ]; then
		timeout "${GH_TIMEOUT}" gh api "users/${owner}" --silent >/dev/null 2>&1
	else
		http_code="$(curl --silent --max-time "${GH_TIMEOUT}" --fail --head --output /dev/null --write-out "%{http_code}\n" "https://api.${GH_HOST}/users/${owner}" 2>/dev/null)"

		if [ "${http_code}" = '200' ]; then
			return 0
		elif [ "${http_code}" = '404' ]; then
			return 1
		elif [ "${http_code}" = '403' ]; then
			echo_error 'GitHub API rate limit exceeded, wait or use the gh cli'
			exit 1
		else
			echo_error "unknown GitHub error: ${http_code}"
			exit 1
		fi
	fi
}

# Usage: gh_owner_has_repo <owner>
gh_owner_has_repo() {
	local owner public_repos
	owner="${1}"
	public_repos=0

	if [ "${USE_GH_CLI}" = 'true' ]; then
		public_repos="$(timeout "${GH_TIMEOUT}" gh api "users/${owner}" --jq '.public_repos' 2>/dev/null)"
	else
		public_repos="$(curl --silent --max-time "${GH_TIMEOUT}" "https://api.${GH_HOST}/users/${owner}" 2>/dev/null | awk -F: '/public_repos/ {gsub(/[^0-9]/,"", $2); print $2}' 2>/dev/null)"
	fi
	[ "${public_repos}" -gt 0 ]
}

# Usage: is_gh_fork <repo_path>
is_gh_fork() {
	local repo_path is_fork
	repo_path="${1}"
	is_fork='false'

	if [ "${USE_GH_CLI}" = 'true' ]; then
		is_fork="$(timeout "${GH_TIMEOUT}" gh repo view "${repo_path}" --json isFork --jq '.isFork' 2>/dev/null)"
	else
		is_fork="$(curl --silent --max-time "${GH_TIMEOUT}" "https://api.${GH_HOST}/repos/${repo_path}" 2>/dev/null | awk -F: '/"fork"/ {gsub(/[^a-zA-Z]/,"", $2); print $2; exit}')"
	fi
	[ "${is_fork}" = 'true' ]
}

# Usage: get_authors_csv <input_dir>
# Output: ${AUTHORS}
get_authors_csv() {
	local input_dir line
	input_dir="${1}"
	AUTHORS='\n'

	while read -r line && [ -n "${line}" ]; do
		AUTHORS+="${line}\n"
	done <<<"$(git -C "${input_dir}" log --format='%ae,"%an"' --all --quiet)"
	AUTHORS="$(echo -e "${AUTHORS}")"
}

# Usage: clone <repo_url> <output_dir>
clone() {
	local repo_url output_dir ret_error
	repo_url="${1}"
	output_dir="${2}"
	ret_error=1

	if [ -d "${output_dir}" ]; then

		# Handle local .git(s) update
		if [ "${UPDATE}" = 'true' ]; then
			echo -n ' Updating...'
			if git -C "${output_dir}" pull --quiet >/dev/null 2>&1; then
				ret_error=0
			else
				echo -n ' Failed.'

				# Attempt to clone the repo in a temp dir
				if repo_exist_not_empty "${repo_url}"; then
					echo -n ' Downloading...'
					if git clone --no-checkout --quiet "${repo_url}" "_${output_dir}" >/dev/null 2>&1; then
						rm -rf "${output_dir:?}" && \n
							mv -f "_${output_dir}" "${output_dir}" && \n
							ret_error=0
					else
						echo_error "repository out of reach: ${repo_url%.git}"
					fi
				else
					ret_error=0
					echo -n ' Repo empty, skipping...'
				fi
			fi
		else
			ret_error=0
		fi
	else
		echo -n ' Downloading...'
		if repo_exist_not_empty "${repo_url}"; then
			if git clone --no-checkout --quiet "${repo_url}" "${output_dir}" >/dev/null 2>&1; then
				ret_error=0
			else
				echo_error "repository out of reach: ${repo_url%.git}"
			fi
		else
			ret_error=0
			echo -n ' Repo empty, skipping...'
		fi
	fi

	return "${ret_error}"
}

# Usage: scan_repo_list <repo_array>
# Output: ${TOTAL_AUTHORS}
scan_repo_list() {
	local len_repo_list repo counter clone_dir
	read -r TOTAL_AUTHORS repo <<<''
	len_repo_list="$(wc -w <<<"${1}" | tr -d ' ')"
	counter=1

	for url in ${1}; do
		if [ "${url}" = '*/.git' ]; then
			repo="$(basename "${url%%/.git}")"
		else
			repo="$(basename "${url%%.git}")"
		fi

		echo -en "\n[${GREEN}${counter}/${len_repo_list}${NO_COLOR}] - ${BOLD_WHITE}${repo}${NO_COLOR}:"

		# If no download then no temp dir is required
		if [ "${url%://*}" = 'file' ]; then
			clone_dir="${url#*://}"
			if [ "${UPDATE}" = 'true' ]; then

				# Continue on clone fail if list is more than 1
				if ! clone "${url}" "${clone_dir%.git}" && [ "${len_repo_list}" -eq 1 ]; then
					exit 1
				fi
			fi
		else

			# Continue on clone fail if list is more than 1
			clone_dir="${TEMP_DIR}/${repo}"
			if ! clone "${url}" "${clone_dir}" && [ "${len_repo_list}" -eq 1 ]; then
				exit 1
			fi
		fi

		if [ -d "${clone_dir}" ]; then
			echo -n ' Parsing...'
			get_authors_csv "${clone_dir}"
			TOTAL_AUTHORS+="${AUTHORS:-}"
			echo -en " ${GREEN}Done${NO_COLOR}"
		fi

		counter=$((counter + 1))
	done
}

# Usage: output_results <authors_array>
output_results() {
	local authors author_count header
	authors="${1}"
	author_count="$(sed "/^ *$/d" <<<"${authors}" | wc -l)"

	if [ "${author_count}" -le 0 ]; then
		echo -e "\n[${GREEN}i${NO_COLOR}] - No email matching criterias found."
	else
		echo -e "\n\n${authors}"

		if [ -n "${OUTPUT_FILE}" ]; then
			if [ "${INCLUDE_NAME}" = true ]; then
				header='email,names'
			else
				header='email'
			fi
			echo -e "${header}\n${authors}" >"${OUTPUT_FILE:?}"
			echo -e "\n[${GREEN}i${NO_COLOR}] - Results saved to ${BOLD_WHITE}${OUTPUT_FILE}${NO_COLOR}"
		fi
	fi
}

# Usage: get_repo_list_local <input_dir>
# Output: ${REPO_LIST}
get_repo_list_local() {
	local input_dir local_git_list git_path git_path_absolute
	input_dir="${1}"

	# Add all .git(s) to list
	local_git_list="$(find "${input_dir}" -maxdepth 3 -type f -name 'description' ! -size 0)"
	if [ -n "${local_git_list}" ]; then
		while read -r git_path; do
			git_path_absolute="$(realpath "${git_path%%/description}")"
			if repo_exist_not_empty "${git_path_absolute}"; then
				REPO_LIST+="file://${git_path_absolute} "
			else
				echo_error "directory is not a Git repository: $(basename "${git_path_absolute}")"
				usage
				exit 1
			fi
		done <<<"${local_git_list}"
	else
		echo_error 'empty directory'
		usage
		exit 1
	fi
}

# Usage: get_gh_owner_repo_list <owner>
# Output: ${REPO_LIST}
get_gh_owner_repo_list() {
	local owner owner_type owner_api_type repo_url response repo_list
	owner="${1}"

	if [ "${USE_GH_CLI}" = 'true' ]; then
		owner_type="$(timeout "${GH_TIMEOUT}" gh api "users/${owner}" --jq '.type' 2>/dev/null)"
	else
		owner_type="$(curl --silent --max-time "${GH_TIMEOUT}" "https://api.${GH_HOST}/users/${owner}" 2>/dev/null | awk -F: '/"type"/ {gsub(/[^a-zA-Z]/,"", $2); print $2}')"
	fi

	if [ "${owner_type}" = 'Organization' ]; then
		owner_api_type='orgs'
	elif [ "${owner_type}" = 'User' ]; then
		owner_api_type='users'
	else
		echo_error "owner type unsupported: ${owner}"
		usage
		exit 1
	fi

	if [ "${USE_GH_CLI}" = 'true' ]; then
		repo_list="$(timeout "${GH_TIMEOUT}" gh api "${owner_api_type}/${owner}/repos" --paginate --jq ".[] | if ${INCLUDE_FORK} then . else select(.fork==false) end | .clone_url")"
	else
		response="$(curl --silent --max-time "${GH_TIMEOUT}" "https://api.${GH_HOST}/${owner_api_type}/${owner}/repos" 2>/dev/null)"
		repo_list="$(awk -v include_fork="${INCLUDE_FORK}" '
			BEGIN { RS = ""; FS = "\n"; }
			{
				fork_value = clone_url = "";
				for (i = 1; i <= NF; i++) {
					if ($i ~ /"fork":/) {
						gsub(/.*"fork": |,/, "", $i);
						fork_value = $i;
					}
					if ($i ~ /"clone_url":/) {
						gsub(/.*"clone_url": "|",/, "", $i);
						clone_url = $i;
					}
				}
				if ((include_fork == "true" || fork_value == "false") && clone_url != "") {
					print clone_url;
				}
			}' <<<"${response}")"
	fi

	while read -r repo_url && [ -n "${repo_url}" ]; do
		REPO_LIST+="${repo_url} "
	done <<<"${repo_list}"
}

# Usage: filter <authors_array>
# Output: ${FILTERED_LIST}
filter() {
	local authors filters
	authors="${1}"
	FILTERED_LIST=''

	if [ "${USE_FILTERS}" = 'true' ]; then
		# Remove protected and bot emails
		filters="'^$' -e @users.noreply.github.com -e actions@github.com${USER_FILTERS}"
	else
		# Remove empty lines
		# shellcheck disable=SC2089
		filters="'^$'${USER_FILTERS}"
	fi

	# Sort unique lines
	FILTERED_LIST="$(sort --unique --ignore-case <<<"${authors}")"

	# Apply user filters
	# shellcheck disable=SC2086,SC2090
	FILTERED_LIST="$(grep --fixed-strings --invert-match --regexp=${filters} <<<"${FILTERED_LIST}")"

	# Filter names
	FILTERED_LIST="$(
		awk -v yellow="${YELLOW}" -v no_color="${NO_COLOR}" -v include_name="${INCLUDE_NAME}" '
    BEGIN {
        FS = OFS = "," # Set the input and output field separators to comma
    }
    /^[ \t]*$/ {
        next # Skip lines that are empty or contain only spaces
    }
    NF > 1 {
        # If the first field (email) is empty, set it to a placeholder with yellow color
        if ($1 == "") $1 = "(" yellow "No Email" no_color ")";

        # If INCLUDE_NAME is not true, only store the email
        if (include_name != "true") {
            a[$1] = "";  # Store email only
        } else {
            # If the second field (name) is empty, set it to a placeholder with yellow color
            if ($2 == "") $2 = "(" yellow "No Name" no_color ")";
            a[$1] = a[$1]""$2" ";  # Store email and name
        }
    }
    END {
        # Print the processed list
        for (i in a) {
            if (include_name != "true") {
                print i;  # Print email only
            } else {
                print i, a[i]; # Print email and associated names
            }
        }
    }
    ' <<<"${FILTERED_LIST}"
	)"
}

# Parse arguments
REPO_LIST=''
parse_args "${@}"

startup_msg="- Starting scan ${SCAN_NAME:+of }${BOLD_WHITE}${SCAN_NAME:-}${NO_COLOR} -"
startup_msg_length="$(echo -en "${startup_msg}" | sed -E "s/\x1B\[[0-9;]*m//g" | wc -c)"
startup_dashes="$(printf -- '-%0.s' $(seq 1 "${startup_msg_length}"))"

echo "${startup_dashes}"
echo -e "${startup_msg}"
echo -e "${startup_dashes}"

# Handle download dir
if [ "${KEEP_DOWNLOADS}" = 'true' ]; then
	if [ -n "${INPUT_FILE}" ]; then
		TEMP_DIR="${INPUT_FILE%.*}"
	else
		TEMP_DIR="${SCAN_NAME}"
	fi
	echo_info "Keeping downloaded .git in ${BOLD_WHITE}${TEMP_DIR}${NO_COLOR}"
else
	TEMP_DIR="$(mktemp -d -q)"
fi
[ ! -d "${TEMP_DIR}" ] && mkdir -p "${TEMP_DIR:?}"

# Handle errors and exit
trap on_error ERR INT

scan_repo_list "${REPO_LIST}"
filter "${TOTAL_AUTHORS}"
output_results "${FILTERED_LIST}"
clean
