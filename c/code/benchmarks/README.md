# Benchmarks

Run the benchmarks script `run.sh` on the machine you want to benchmark.
Before running the script, configure the first section to fit your needs.
To retrieve data feasible for analysis, consider editing the format string `TIME_FORMAT_DD_CSV`.
The format is equal to the options provided by the `/usr/bin/time` command.

```sh
$ /benchmarks/run.sh
```

The benchmark files are saved to the directory from where the script is executed (cwd).
Files have the operations that they were benchmarked for as a filename prefix (`read_` or `write_`).
The files are valid CSV and can easily be used for further analysis.
