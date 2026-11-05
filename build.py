#!/usr/bin/env python3
"""兼容旧构建命令；统一使用 Node.js 生产构建，避免重建 Pages 产物。"""
import pathlib
import subprocess
import sys
sys.exit(subprocess.call(['node', 'build.js'], cwd=pathlib.Path(__file__).resolve().parent))
