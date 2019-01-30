__all__ = ("get_git_version")

from subprocess import Popen, PIPE
import os


def call_git_rev_parse():

	try:
		p = Popen(['git', 'rev-parse', 'HEAD'], stdout=PIPE, stderr=PIPE)
		p.stderr.close()
		line = "Git commit ID: " + p.stdout.readlines()[0]
		p = Popen(['date', '-u', '+%m-%d-%Y.%H:%M:%S.UTC'], stdout=PIPE, stderr=PIPE)
		p.stderr.close()
		line = line + "Build time: " + p.stdout.readlines()[0]
		return line.strip()

	except:
		return None


def read_release_version():
	try:
		script_dir = os.path.dirname(__file__)
		with open(script_dir + "/acc_provision/RELEASE-VERSION", "r") as f:
			version = f.readlines()[0]
			f.close()
			return version.strip()

	except:
		return None


def write_release_version(version):
	script_dir = os.path.dirname(__file__)
	with open(script_dir + "/acc_provision/RELEASE-VERSION", "w") as f:
		f.write("%s\n" % version)
		f.close()


def get_git_version():
	# Read in the version that's currently in RELEASE-VERSION.
	release_version = read_release_version()

	version = call_git_rev_parse()

	# If that doesn't work, fall back on the value that's in
	# RELEASE-VERSION.

	if version is None:
		version = release_version

	# If we still don't have anything:

	if version is None:
		version = "Release info not in the current build."
		return version


	# If the current version is different from what's in the
	# RELEASE-VERSION file, update the file to be current.

	if version != release_version:
		write_release_version(version)

	# Finally, return the current version.

	return version


if __name__ == "__main__":
	print(get_git_version())
