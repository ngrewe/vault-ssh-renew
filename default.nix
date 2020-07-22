with import <nixpkgs> {}; {
  fEnv = stdenv.mkDerivation {
    name = "vault-ssh-renew";
    buildInputs = [
      stdenv
      idea.pycharm-community
      python37Packages.poetry
      
    ];
    shellHook = "poetry install";
  };
}

