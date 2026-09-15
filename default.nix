# ReconPro Nix package.
#
# NOTE (honest): this expression is validated by inspection only — the
# build sandbox has NO nix binary, so `nix-build` was never executed here.
# Runtime core dependencies mirror requirements.txt/pyproject:
#   rich, textual, requests (pure-python core; optional extras like
#   playwright/scapy are deliberately NOT propagated).
{
  lib,
  python3Packages,
  src ? ./.,
}:

python3Packages.buildPythonPackage rec {
  pname = "reconpro";
  version = "11.1.0";
  format = "pyproject";
  pyproject = true;

  inherit src;

  propagatedBuildInputs = with python3Packages; [
    rich
    textual
    requests
  ];

  # The full pytest suite has a known hang; CI covers the chunked subset
  # (tools/ci_test_groups.txt). Keep the nix build hermetic and fast.
  doCheck = false;

  pythonImportsCheck = [ "reconpro" ];

  meta = {
    description = "ReconPro v11 — Enterprise Security Reconnaissance Platform";
    longDescription = ''
      28 Modules. 77 Commands. MITRE ATT&CK. SARIF/PDF/CSV.
      Pure Python security reconnaissance CLI.
    '';
    homepage = "https://reconpro.io";
    changelog = "https://reconpro.io/changelog";
    license = lib.licenses.mit;
    mainProgram = "reconpro";
    maintainers = [ ];
    platforms = lib.platforms.unix;
  };
}
