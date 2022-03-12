{
  description = ''Application to detect which commit generates malicious code detection by antivirus software.'';

  inputs.flakeNimbleLib.owner = "riinr";
  inputs.flakeNimbleLib.ref   = "master";
  inputs.flakeNimbleLib.repo  = "nim-flakes-lib";
  inputs.flakeNimbleLib.type  = "github";
  inputs.flakeNimbleLib.inputs.nixpkgs.follows = "nixpkgs";
  
  inputs.src-mcd-develop.flake = false;
  inputs.src-mcd-develop.owner = "malicious-commit-detector";
  inputs.src-mcd-develop.ref   = "refs/heads/develop";
  inputs.src-mcd-develop.repo  = "mcd";
  inputs.src-mcd-develop.type  = "gitlab";
  
  inputs."parsetoml".dir   = "nimpkgs/p/parsetoml";
  inputs."parsetoml".owner = "riinr";
  inputs."parsetoml".ref   = "flake-pinning";
  inputs."parsetoml".repo  = "flake-nimble";
  inputs."parsetoml".type  = "github";
  inputs."parsetoml".inputs.nixpkgs.follows = "nixpkgs";
  inputs."parsetoml".inputs.flakeNimbleLib.follows = "flakeNimbleLib";
  
  inputs."cligen".dir   = "nimpkgs/c/cligen";
  inputs."cligen".owner = "riinr";
  inputs."cligen".ref   = "flake-pinning";
  inputs."cligen".repo  = "flake-nimble";
  inputs."cligen".type  = "github";
  inputs."cligen".inputs.nixpkgs.follows = "nixpkgs";
  inputs."cligen".inputs.flakeNimbleLib.follows = "flakeNimbleLib";
  
  inputs."colorizeecho".dir   = "nimpkgs/c/colorizeecho";
  inputs."colorizeecho".owner = "riinr";
  inputs."colorizeecho".ref   = "flake-pinning";
  inputs."colorizeecho".repo  = "flake-nimble";
  inputs."colorizeecho".type  = "github";
  inputs."colorizeecho".inputs.nixpkgs.follows = "nixpkgs";
  inputs."colorizeecho".inputs.flakeNimbleLib.follows = "flakeNimbleLib";
  
  outputs = { self, nixpkgs, flakeNimbleLib, ...}@deps:
  let 
    lib  = flakeNimbleLib.lib;
    args = ["self" "nixpkgs" "flakeNimbleLib" "src-mcd-develop"];
  in lib.mkRefOutput {
    inherit self nixpkgs ;
    src  = deps."src-mcd-develop";
    deps = builtins.removeAttrs deps args;
    meta = builtins.fromJSON (builtins.readFile ./meta.json);
  };
}