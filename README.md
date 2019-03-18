
#自动扫描摄像头说明
 

作者： sleeping
邮箱： ping.li@nazhiai.com

 ---

## Linux版本编译测试(默认为Release版本)

* Release版本
    进入目录onvif-cmake/build下，执行如下命令:
```
    cmake ..
```
    然后会生成Makefile文件，执行make会在onvif-cmake/exe下生成libnzscan.so库文件和测试文件scan,执行scan即可

* Debug版本
    进入目录onvif-cmake/build下，执行如下命令:
```
    cmake .. -DCMAKE_BUILD_TYPE=Debug
```
    然后会生成Makefile文件，执行make会在onvif-cmake/exe下生成libnzscand.so库文件和测试文件scand,执行scand即可
    
***注:Debug版本可使用gdb调试，故体积较大***
    

## Windows版本编译测试(默认为Release版本)

* Release版本
    进入onvif-cmake/build目录下,执行如下命令：
```
        mkdir Release
        cd Release
        cmake ../.. -G "Visual Studio 12 2013 Win64"
```
    生成工程目录后，根据openssl的安装路径配置include路径和库路径即可

* Debug版本
    进入onvif-cmake/build目录下,执行如下命令：
```
        mkdir Debug
        cd Debug
        cmake ../.. -G "Visual Studio 12 2013 Win64" -DCMAKE_BUILD_TYPE=Debug
```
    生成工程目录后，根据openssl的安装路径配置include路径和库路径即可

---

***注:暂不支持跨网段搜索设备***
