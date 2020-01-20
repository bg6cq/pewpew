
### 安装过程

```
yum install -y nodejs npm
npm config set strict-ssl false
npm install
```


### 数据流

```
whoisscanme  ------(UDP 4001)----->  portscan_event.php  -----(UDP 4000)------> node js
```

### 运行过程

```
node app.js
```


