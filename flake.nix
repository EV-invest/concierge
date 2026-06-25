{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks.url = "github:cachix/git-hooks.nix";
  };
  outputs = { self, nixpkgs, rust-overlay, flake-utils, pre-commit-hooks }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          allowUnfree = true;
        };
        # NB: can't load rust-bin from nightly.latest, as there are weak guarantees
        # of which components will be available on each day.
        rust = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default.override {
          extensions = [ "rust-src" "rust-analyzer" "rust-docs" "rustc-codegen-cranelift-preview" ];
          targets = [ "wasm32-unknown-unknown" ];
        });
        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            treefmt = {
              enable = true;
              packageOverrides.treefmt = pkgs.treefmt;
            };
          };
        };

        # ── shared shims ────────────────────────────────────────────────────
        # rust-lld (wasm32 linker) embeds the wrong rpath on macOS — it looks for
        # libLLVM.dylib in bin/../lib/ but Nix puts it one level up in lib/.
        # The FALLBACK var only kicks in when normal resolution fails — exactly
        # rust-lld's case, never clang's (which would otherwise be forced onto
        # rustc's older libLLVM when linking host proc-macros).
        dyldFallback = ''export DYLD_FALLBACK_LIBRARY_PATH="${rust}/lib''${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"'';
        # tonic-build / prost-build shell out to protoc; point them at nixpkgs'.
        protocEnv = ''export PROTOC="${pkgs.protobuf}/bin/protoc"'';

        # ── concierge (the modular-monolith runner: all gRPC modules in-process) ──
        # Runs the `concierge` binary, which mounts the auth/directory/notification/
        # log modules as in-process gRPC services and applies its DB migrations on
        # boot. Needs Postgres (`.#db`); defaults below fill anything left unset.
        runConcierge = pkgs.writeShellApplication {
          name = "run-concierge";
          runtimeInputs = with pkgs; [ rust pkg-config protobuf git ];
          text = ''
            ${dyldFallback}
            ${protocEnv}
            repo="$(git rev-parse --show-toplevel)"
            cd "$repo"

            set -a
            if [ -f .env ]; then
              # shellcheck disable=SC1091
              . .env
            fi
            set +a

            export DATABASE_URL="''${DATABASE_URL:-postgres://postgres@localhost:5432/ev_concierge}"
            export CONCIERGE_BIND="''${CONCIERGE_BIND:-0.0.0.0:50061}"
            export RUST_LOG="''${RUST_LOG:-info,concierge=debug,evconcierge_auth=debug}"
            exec cargo run -p concierge
          '';
        };

        # ── local Postgres ──────────────────────────────────────────────────
        # Project-local dev database under .pg/ (gitignored). First run initdb's a
        # trust-auth cluster and creates the database; later runs just start it.
        runPostgres = pkgs.writeShellApplication {
          name = "run-postgres";
          runtimeInputs = with pkgs; [ postgresql git coreutils gnugrep ];
          text = ''
            repo="$(git rev-parse --show-toplevel)"
            export PGDATA="$repo/.pg/data"
            sockets="$repo/.pg/sockets"
            port="''${PGPORT:-5432}"
            dbs="''${PGDATABASES:-ev_concierge}"

            mkdir -p "$sockets"
            if [ ! -s "$PGDATA/PG_VERSION" ]; then
              echo "initialising postgres cluster in $PGDATA"
              initdb --username=postgres --auth=trust --pgdata="$PGDATA" >/dev/null
            fi
            chmod 0700 "$PGDATA"

            (
              until pg_isready --host="$sockets" --port="$port" --quiet; do sleep 0.2; done
              for db in $dbs; do
                if ! psql --host="$sockets" --port="$port" --username=postgres --dbname=postgres \
                       --tuples-only --no-align \
                       --command "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1; then
                  createdb --host="$sockets" --port="$port" --username=postgres "$db"
                  echo "created database '$db'"
                fi
              done
              echo "postgres ready on 127.0.0.1:$port (databases: $dbs, user 'postgres', trust auth)"
            ) &

            exec postgres -D "$PGDATA" -k "$sockets" -h 127.0.0.1 -p "$port"
          '';
        };
      in
      {
        # `nix run .#concierge` → the runner binary (auth/directory/notification/log modules in-process; applies DB migrations on boot, needs `.#db`)
        # `nix run .#db`        → local Postgres only (creates ev_concierge)
        apps = {
          concierge = { type = "app"; program = "${runConcierge}/bin/run-concierge"; };
          db = { type = "app"; program = "${runPostgres}/bin/run-postgres"; };
        };

        devShells.default =
          with pkgs;
          mkShell {
            inherit (pre-commit-check) shellHook;

            packages = [
              openssl
              pkg-config
              protobuf
              clang-tools
              rust
              sccache
              mold
              postgresql
              treefmt
              nixpkgs-fmt
            ] ++ pre-commit-check.enabledPackages;

            env.RUST_BACKTRACE = 1;
            env.RUST_LIB_BACKTRACE = 0;
            env.PROTOC = "${pkgs.protobuf}/bin/protoc";
            env.DYLD_FALLBACK_LIBRARY_PATH = "${rust}/lib";
            # shared compile cache across builds; incremental off (incompatible with sccache)
            env.RUSTC_WRAPPER = "sccache";
            env.CARGO_INCREMENTAL = "0";
          };
      }
    );
}
