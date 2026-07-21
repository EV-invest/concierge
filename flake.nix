{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    v_flakes.url = "github:valeratrades/v_flakes?ref=v1.6";
    v_flakes.inputs.nixpkgs.follows = "nixpkgs";
    v_flakes.inputs.rust-overlay.follows = "rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks.url = "github:cachix/git-hooks.nix";
    pre-commit-hooks.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, rust-overlay, v_flakes, flake-utils, pre-commit-hooks }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          allowUnfree = true;
        };
        # Canonical toolchain pinned in v_flakes — byte-identical across repos, so
        # the nix store dedups it and sccache cross-references compilations.
        rust = v_flakes.rs.default_nightly system;
        # Lean toolchain for the production image build: rustc + cargo + std only,
        # keeping the fat dev toolchain out of the release closure (mirrors site_conductor).
        rustBuild = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal);
        pname = "concierge";
        runnerCargo = (builtins.fromTOML (builtins.readFile ./runner/Cargo.toml)).package;

        rs = v_flakes.rs { inherit pkgs rust; };
        github = v_flakes.github {
          inherit pkgs pname rs;
          enable = true;
          # Public repo → public Cachix (`ev-invest`); pull deps + push built paths.
          cache = { cachix = "ev-invest"; };
          lastSupportedVersion = "nightly-2026-05-12";
          containerRelease = { registry = "ghcr.io/ev-invest"; };
          gitignore.extra = ''
            ## Local Postgres
            .pg/
            ## Env
            .env
            .env.local
            ## App config
            /config.toml
            config.toml
            ## LLMs
            AGENTS.md
            CLAUDE.md
            .claude/
            .pre-commit-config.yaml
          '';
        };
        combined = v_flakes.utils.combine { inherit rust; modules = [ rs github ]; };

        # ── production runner: binary + OCI image ───────────────────────────
        rustPlatform = pkgs.makeRustPlatform { cargo = rustBuild; rustc = rustBuild; };
        conciergeSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          # .cargo holds dev-only accelerators (sccache rustc-wrapper) the hermetic
          # sandbox lacks — let nix's vendor config drive the build instead.
          filter = path: _type:
            ! builtins.elem (baseNameOf path) [ "target" ".direnv" ".git" ".cargo" "tmp" "result" ];
        };
        conciergeBin = rustPlatform.buildRustPackage {
          pname = runnerCargo.name;
          version = runnerCargo.version;
          src = conciergeSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "concierge" "--bin" "concierge" ];
          nativeBuildInputs = with pkgs; [ protobuf pkg-config ];
          buildInputs = [ pkgs.openssl ];
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          doCheck = false;
        };
        # ONE container: the runner binary serves gRPC (:55670) AND the auth web
        # surface (:55671) in-process. The contract's port/healthPath describe the
        # web surface (http probes); gitops patches the Service to expose both.
        # Secret env (signing key, JWKS, Google OAuth, bridge token) arrives via
        # the automatic optional `kubernetes-concierge` envFrom — never baked in.
        # Topology literals are set directly as contract env vars (read by
        # ev::settings! from_env). deploy/config.nix is kept for reference only.
        inherit pkgs pname;
        containers."" = {
          port = 55671;
          healthPath = "/health";
          criticality = "normal";
          entrypoint = [ "/bin/concierge" ];
          contents = [ conciergeBin ];
          env = {
            DATABASE_URL = "postgres://evinvest@10.42.0.1:5432/concierge";
            REDIS_URL = "redis://10.42.0.1:6379/1";
            # The inbound verifier dials its own in-process Jwks RPC over loopback.
            AUTH_JWKS_GRPC_ENDPOINT = "http://127.0.0.1:55670";
            AUTH_SIGNING_KID = "prod-1";
            RUST_LOG = "info";
            # These env vars are read directly by ev::settings! (from_env).
            # deploy/config.nix is kept for reference.
            BIND = "0.0.0.0:55670";
            WEB_BIND = "0.0.0.0:55671";
            PUBLIC_ORIGIN = "https://evinvest.ltd";
            APP_ENV = "production";
          };
        };
        };
        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            treefmt = {
              enable = true;
              packageOverrides.treefmt = pkgs.treefmt;
              # Auto-format and re-stage instead of failing the commit; resolved from
              # PATH (the dev shell provides treefmt) so the generated hook survives
              # store-path churn. Mirrors banking's hook shape.
              entry = pkgs.lib.mkForce "bash -c 'treefmt --no-cache \"$@\" && git add -u' --";
              # `git add -u` needs exclusive access to the index lock.
              require_serial = true;
            };
          };
        };

        # ── ev_invest dev topology (single source of truth for ports) ───────
        # ONE postgres + ONE redis serve every sibling repo (banking mirrors these
        # values in its flake). Postgres database name == app name. Redis has no
        # named dbs — numeric mapping: 0=banking, 1=concierge.
        ports = {
          POSTGRES_PORT = "5432";
          REDIS_PORT = "6379";
          CONCIERGE_PORT = "55670";
          # The site-level auth HTTP surface (runner/src/web); the conductor
          # rewrites /api/auth/* + /api/callback/auth/* here.
          CONCIERGE_WEB_PORT = "55671";
        };
        # DEFAULTS, not overrides: anything already set in the environment (or a
        # sourced `.env`) wins — machines with non-standard ports stay working.
        portEnv = pkgs.lib.concatStrings (pkgs.lib.mapAttrsToList (n: v: "export ${n}=\"\${${n}:-${v}}\"\n") ports);

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
        # boot. Ensures the SHARED postgres + redis first, then fills topology
        # defaults; anything already set in the environment or `.env` wins.
        runConcierge = pkgs.writeShellApplication {
          name = "run-concierge";
          runtimeInputs = with pkgs; [ rust clang mold pkg-config protobuf git ];
          text = ''
            ${dyldFallback}
            ${protocEnv}
            repo="$(git rev-parse --show-toplevel)"
            cd "$repo"

            ${runPostgres}/bin/run-postgres
            ${runRedis}/bin/run-redis

            set -a
            if [ -f .env ]; then
              # shellcheck disable=SC1091
              . .env
            fi
            set +a

            ${portEnv}
            export DATABASE_URL="''${DATABASE_URL:-postgres://postgres@localhost:$POSTGRES_PORT/concierge}"
            # Env aliases mirror AppConfig field names (ev::settings! from_env).
            export BIND="''${BIND:-0.0.0.0:$CONCIERGE_PORT}"
            export WEB_BIND="''${WEB_BIND:-0.0.0.0:$CONCIERGE_WEB_PORT}"
            export REDIS_URL="''${REDIS_URL:-redis://127.0.0.1:$REDIS_PORT/1}"
            # The inbound verifier dials its own in-process Jwks RPC.
            export AUTH_JWKS_GRPC_ENDPOINT="''${AUTH_JWKS_GRPC_ENDPOINT:-http://127.0.0.1:$CONCIERGE_PORT}"
            # Shared bridge token the banking money plane presents on PullUserLifecycle.
            export BRIDGE_SERVICE_TOKEN="''${BRIDGE_SERVICE_TOKEN:-dev-bridge-token}"
            # ev::settings! defaults to "development"/None for Option fields;
            # dev topology is owned here, deploy/config.nix kept for reference.
            export APP_ENV="''${APP_ENV:-development}"
            export PUBLIC_ORIGIN="''${PUBLIC_ORIGIN:-http://localhost:58843}"
            export RUST_LOG="''${RUST_LOG:-info,concierge=debug,evconcierge_auth=debug}"
            exec cargo run -p concierge
          '';
        };

        # ── shared Redis (ensure-running) ───────────────────────────────────
        # ONE instance for all ev_invest repos (numeric dbs: 0=banking, 1=concierge),
        # daemonized under the user state dir so no repo's dev-stack exit can yank it
        # out from under the siblings. Stop: redis-cli -p $REDIS_PORT shutdown nosave
        runRedis = pkgs.writeShellApplication {
          name = "run-redis";
          runtimeInputs = with pkgs; [ redis coreutils ];
          text = ''
            ${portEnv}
            state="''${XDG_STATE_HOME:-$HOME/.local/state}/ev_invest"
            mkdir -p "$state/redis"
            if ! redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
              # AOF on: auth sessions + refresh families live here, and without
              # persistence every redis restart signs everyone out.
              redis-server --port "$REDIS_PORT" --dir "$state/redis" --save "" --appendonly yes \
                --daemonize yes --logfile "$state/redis/log"
            fi
            echo "redis ready on 127.0.0.1:$REDIS_PORT"
          '';
        };

        # ── shared Postgres (ensure-running) ────────────────────────────────
        # ONE trust-auth cluster for all ev_invest repos, under the user state dir —
        # NOT the repo. Started detached (same reasoning as redis above); each repo's
        # runner only ensures its own databases exist (database name == app name).
        # Stop: pg_ctl -D ~/.local/state/ev_invest/pg/data stop
        runPostgres = pkgs.writeShellApplication {
          name = "run-postgres";
          runtimeInputs = with pkgs; [ postgresql coreutils gnugrep util-linux ];
          text = ''
            ${portEnv}
            state="''${XDG_STATE_HOME:-$HOME/.local/state}/ev_invest"
            export PGDATA="$state/pg/data"
            sockets="$state/pg/sockets"
            dbs="''${PGDATABASES:-concierge}"
            mkdir -p "$sockets"

            # Serialize sibling repos racing to first-boot the shared cluster.
            exec 9>"$state/pg.lock"
            flock 9

            if ! pg_isready --host="$sockets" --port="$POSTGRES_PORT" --quiet; then
              # TCP answering while our socket is silent = some OTHER cluster owns
              # the port — refuse rather than silently use the wrong database.
              if pg_isready --host=127.0.0.1 --port="$POSTGRES_PORT" --quiet; then
                echo "error: 127.0.0.1:$POSTGRES_PORT serves a postgres that is not the shared ev_invest cluster" >&2
                exit 1
              fi
              if [ ! -s "$PGDATA/PG_VERSION" ]; then
                echo "initialising shared postgres cluster in $PGDATA"
                initdb --username=postgres --auth=trust --pgdata="$PGDATA" >/dev/null
              fi
              chmod 0700 "$PGDATA"
              # 9>&-: the daemon must NOT inherit the lock fd, or it would hold the
              # flock for its whole lifetime and deadlock every future ensure run.
              pg_ctl -D "$PGDATA" -l "$state/pg/log" -o "-k $sockets -h 127.0.0.1 -p $POSTGRES_PORT" start 9>&-
            fi

            for db in $dbs; do
              if ! psql --host="$sockets" --port="$POSTGRES_PORT" --username=postgres --dbname=postgres \
                     --tuples-only --no-align \
                     --command "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1; then
                createdb --host="$sockets" --port="$POSTGRES_PORT" --username=postgres "$db"
                echo "created database '$db'"
              fi
            done
            echo "postgres ready on 127.0.0.1:$POSTGRES_PORT (databases ensured: $dbs)"
          '';
        };
        # ── bump latest remote vX.Y.Z tag and push: `.#publish major|minor|patch` ──
        runPublish = pkgs.writeShellApplication {
          name = "publish";
          runtimeInputs = with pkgs; [ git ];
          text = ''
                        part="''${1:-}"
                        case "$part" in major|minor|patch) ;; *) echo "usage: nix run .#publish -- major|minor|patch" >&2; exit 1 ;; esac
                        [ -z "$(git status --porcelain)" ] || { echo "uncommitted changes — commit or stash first" >&2; exit 1; }

                        git fetch --tags --force origin >/dev/null 2>&1
                        last="$(git tag -l 'v*' --sort=-v:refname | head -n1)"
                        ver="''${last#v}"; [ -n "$ver" ] || ver="0.0.0"
                        IFS=. read -r ma mi pa <<EOF
            $ver
            EOF
                        case "$part" in
                          major) ma=$((ma+1)); mi=0; pa=0 ;;
                          minor) mi=$((mi+1)); pa=0 ;;
                          patch) pa=$((pa+1)) ;;
                        esac
                        next="v$ma.$mi.$pa"
                        echo "$last → $next"
                        git tag "$next"
                        git push origin "$next"
          '';
        };
      in
      {
        # `nix run` (default = .#concierge) → the runner binary (auth/directory/notification/log modules in-process; applies DB migrations on boot; ensures shared postgres + redis first)
        # `nix run .#db`        → ensure the SHARED ev_invest Postgres is up (+ this repo's `concierge` database)
        # `nix run .#redis`     → ensure the SHARED ev_invest Redis is up
        # `nix run .#publish`   → bump latest remote vX.Y.Z tag (major|minor|patch) + push
        apps = {
          default = { type = "app"; program = "${runConcierge}/bin/run-concierge"; };
          concierge = { type = "app"; program = "${runConcierge}/bin/run-concierge"; };
          db = { type = "app"; program = "${runPostgres}/bin/run-postgres"; };
          redis = { type = "app"; program = "${runRedis}/bin/run-redis"; };
          publish = { type = "app"; program = "${runPublish}/bin/publish"; };
        };

        packages = {
          default = conciergeBin;
          concierge = conciergeBin;
        } // containerStd.packages;

        containers = containerStd.containers;

        devShells.default =
          with pkgs;
          mkShell {
            shellHook = pre-commit-check.shellHook + combined.shellHook;

            packages = [
              openssl
              pkg-config
              protobuf
              # wrapped clang (knows glibc's crt paths) — cargo config uses linker=clang;
              # NOT clang-tools, which ships an unwrapped clang that shadows the wrapper
              clang
              rust
              sccache
              mold
              postgresql
              redis
              treefmt
              nixpkgs-fmt
            ] ++ pre-commit-check.enabledPackages ++ combined.enabledPackages;

            env.RUST_BACKTRACE = 1;
            env.RUST_LIB_BACKTRACE = 0;
            env.PROTOC = "${pkgs.protobuf}/bin/protoc";
            env.DYLD_FALLBACK_LIBRARY_PATH = "${rust}/lib";
            env.RUSTC_WRAPPER = "sccache";
          };
      }
    );
}
