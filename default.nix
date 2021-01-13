with import <nixpkgs> {};

with python3.pkgs;

buildPythonPackage {
  pname = "kvm-pirate";
  version = "0.0.1";
  src = ./.;
  propagatedBuildInputs = [
    linuxPackages_latest.bcc
  ];
  preCheck = ''
    echo -e "\x1b[32m## run black\x1b[0m"
    LC_ALL=en_US.utf-8 black --check .
    echo -e "\x1b[32m## run flake8\x1b[0m"
    flake8 .
    echo -e "\x1b[32m## run mypy\x1b[0m"
    mypy --strict .

  '';
  checkInputs = [
    pytestCheckHook
    black
    flake8
    mypy
  ];
}
