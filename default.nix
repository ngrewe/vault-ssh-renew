with import <nixpkgs> {}; {
  fEnv = stdenv.mkDerivation {
    name = "vault-ssh-renew";
    buildInputs = [
      stdenv
      idea.pycharm-community
      python37Packages.poetry
      python36
      python37
      python38
      
    ];
    shellHook = "poetry install";
  };
}

