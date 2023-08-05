lca2txt
=======
lca2txt is CLI utility for converting compressed LogRhythm archive files (LCA files) to plain text. The converted log data can be dumped to standard output or relayed to a syslog server

Examples
========
Get help for commands and CLI flags:
```shell
# python main.py --help
# python main.py dump --help
# python main.py relay --help
```

Output to standard output:
```shell
# python main.py dump --archive some_archive_filename.lca
```

Output to a local syslog server on port 1514/UDP:
```shell
# python main.py relay --archive some_archive_filename.lca -s 127.0.0.1 -p 1514
```