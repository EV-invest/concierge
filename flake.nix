{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    v_flakes.url = "github:valeratrades/v_flakes?ref=v1.6";
    v_flakes.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks.url = "github:cachix/git-hooks.nix";
    pre-commit-hooks.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, v_flakes, flake-utils, pre-commit-hooks }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          allowUnfree = true;
        };
        # Canonical toolchain pinned in v_flakes — byte-identical across repos, so
        # the nix store dedups it and sccache cross-references compilations.
        rust = v_flakes.rs.default_nightly system;
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
          runtimeInputs = with pkgs; [ rust pkg-config protobuf git ];
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
            export CONCIERGE_BIND="''${CONCIERGE_BIND:-0.0.0.0:$CONCIERGE_PORT}"
            export REDIS_URL="''${REDIS_URL:-redis://127.0.0.1:$REDIS_PORT/1}"
            # The inbound verifier dials its own in-process Jwks RPC.
            export AUTH_JWKS_GRPC_ENDPOINT="''${AUTH_JWKS_GRPC_ENDPOINT:-http://127.0.0.1:$CONCIERGE_PORT}"
            # Shared bridge token the banking money plane presents on PullUserLifecycle.
            export BRIDGE_SERVICE_TOKEN="''${BRIDGE_SERVICE_TOKEN:-dev-bridge-token}"
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
              redis-server --port "$REDIS_PORT" --dir "$state/redis" --save "" --appendonly no \
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
      in
      {
        # `nix run .#concierge` → the runner binary (auth/directory/notification/log modules in-process; applies DB migrations on boot; ensures shared postgres + redis first)
        # `nix run .#db`        → ensure the SHARED ev_invest Postgres is up (+ this repo's `concierge` database)
        # `nix run .#redis`     → ensure the SHARED ev_invest Redis is up
        apps = {
          concierge = { type = "app"; program = "${runConcierge}/bin/run-concierge"; };
          db = { type = "app"; program = "${runPostgres}/bin/run-postgres"; };
          redis = { type = "app"; program = "${runRedis}/bin/run-redis"; };
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
              redis
              treefmt
              nixpkgs-fmt
            ] ++ pre-commit-check.enabledPackages;

            env.RUST_BACKTRACE = 1;
            env.RUST_LIB_BACKTRACE = 0;
            env.PROTOC = "${pkgs.protobuf}/bin/protoc";
            env.DYLD_FALLBACK_LIBRARY_PATH = "${rust}/lib";
            env.RUSTC_WRAPPER = "sccache";
          };
      }
    );
}
