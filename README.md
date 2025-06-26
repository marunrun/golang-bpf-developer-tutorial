# **bpf-developer-tutorial**

generate from [cilium-ebpf-starter-template](https://github.com/eunomia-bpf/cilium-ebpf-starter-template)

golang example of [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

Some code is from: https://github.com/grafana/beyla

## build

To see all available build options:
```shell
make help
```

Build all projects for the host architecture:
```shell
make all
```

Build a single project:
```shell
make 1-helloworld
```

Build a project for a specific architecture:
```shell
make 1-helloworld-arm64
```

Build all projects for all supported architectures:
```shell
make build-all-archs
```

Clean build artifacts:
```shell
make clean
```
