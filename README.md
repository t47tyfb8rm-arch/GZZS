# 伯俊周会部署版

## 本地运行

```bash
npm install
npm start
```

默认地址：`http://localhost:3000`

## Linux 服务器运行

```bash
export ADMIN_USER=admin
export ADMIN_PASSWORD='请换成强密码'
export APP_USERS='zhangsan:123456,lisi:123456'
export SESSION_SECRET='请换成随机长字符串'
export PORT=3000
npm install
npm start
```

首次启动会自动创建管理员和 `APP_USERS` 中的普通账号。数据保存在 SQLite 文件 `data/app.sqlite`，不要提交到 GitHub。

如果旧版本已经生成过 `data/db.json`，首次启动 SQLite 版本时会自动迁移到 `data/app.sqlite`。迁移成功后可以保留 `db.json` 做备份，也可以确认无误后手动删除。

## 账号权限

- 普通账号：只能看到和修改自己的周会内容、存档。
- 管理员账号：可以看到所有账号的周会内容，并可在页面右上角打开“账号”管理用户。
