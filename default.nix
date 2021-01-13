with import <nixpkgs> {};

with python3.pkgs;

buildPythonPackage {
  pname = "kvm-pirate";
  version = "0.0.1";
  src = ./.;
  propagatedBuildInputs = [
    linuxPackages_latest.bcc
  ];
  checkInputs = [
    pytestCheckHook
  ];
}
