# etpclient-rs
A rust ETP client (use websocket)

## Version History


## License

Licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license (LICENSE-MIT or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

at your option.


## Support

Please enter an issue in the repo for any questions or problems.


## Examples :

```console
cargo run -- -u [ETP_SERVER_URL] --login [LOGIN] --password [PASSWORD]
```


To have the server responses written in a log file : 

```console
cargo run -- -u [ETP_SERVER_URL] --login [LOGIN] --password [PASSWORD] --log-file [LOG_FILE_PATH]
```

### Commands example (during the program run when connexion succeed): 

Dataspaces:

```console
getdataspaces
```
```console
putdataspace test
```
```console
DeleteDataspace test
```

Resources :

```console
getresource
```

```console
getresource eml:///dataspace('volve-eqn')
```

```console
getresource volve-eqn
```

Dataobjects:

```console
getdataobject eml:///dataspace('volve-eqn')/eml20.EpcExternalPartReference(9ba6c0f4-bd26-461f-a6b6-d65c9a22a7b2)
```

```console
getdataobject eml:///dataspace('volve-eqn')/eml20.EpcExternalPartReference(9ba6c0f4-bd26-461f-a6b6-d65c9a22a7b2)
```