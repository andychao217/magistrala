#!/bin/bash
cd /root/magistrala || exit 1
make run DOCKER_PROJECT=magistrala

# 赋予该脚本可执行权限
# chmod +x ~/start_magistrala.sh
#
# 创建一个新的服务文件
# vi /etc/systemd/system/magistrala.service
#
# 在该文件中添加以下内容
# 在 vi 中，按 i 进入插入模式，然后输入你的脚本内容
# [Unit]
# Description=Start Magistrala on boot
# After=multi-user.target
#
# [Service]
# Type=simple
# ExecStart=/bin/bash /root/start_magistrala.sh
# WorkingDirectory=/root/magistrala  # 替换为实际路径
# Restart=on-failure
#
# [Install]
# WantedBy=multi-user.target
# 按 Esc 退出插入模式，然后输入 :wq 保存并退出
#
# 重新加载 systemd 以识别新的服务
# systemctl daemon-reload
#
# 启用服务，以便在启动时自动运行
# systemctl enable magistrala.service
#
# (可选) 你可以立即启动服务以测试它
# systemctl start magistrala.service
#
# 检查服务状态以确保它正在运行
# systemctl status magistrala.service