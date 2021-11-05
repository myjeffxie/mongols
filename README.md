https://bitbucket.org/taishiling/mongols/src/master/

该项目已经过时。

# mongols

A high performance network library for c++:

- Libevent, libev and libuv are outdated.

- Both apache and nginx are very slow.


![nginx_4_worker](benchmark/nginx_4_worker.png)
![mongols_4_worker](benchmark/mongols_4_worker.png)
![nginx_vs_mongols](benchmark/nginx_vs_mongols.png)


## dependency

- linux
- gcc (-std=c11)
- g++ (-std=c++11)
- openssl

## feature

[mongols document](https://mongols.hi-nginx.com)

## install

### libmongols
`make clean && make -j2 && sudo make install && sudo ldconfig`
### libmongols-ext
`cd ext && make clean && make -j2 && sudo make install && sudo ldconfig`

## usage

### libmongols
`pkg-config --libs --cflags mongols openssl zlib`
### libmongols-ext
`pkg-config --libs --cflags mongols-ext mongols openssl zlib`

## binding

[pymongols](https://github.com/webcpp/pymongols)

## example

[example](https://github.com/webcpp/mongols/tree/master/example)
