#!/bin/bash

# 递归查找当前目录下的所有文件（排除 . 开头的目录和文件，以及 .sha1 文件）
find . -type f \
    -not -path '*/.*' \
    -not -name "*.sha1" \
    | while read -r file; do
    # 计算文件的 SHA1 值（仅哈希部分）
    sha1=$(sha1sum "$file" | awk '{print $1}')
    
    # 创建对应的 .sha1 文件名
    sha1_file="${file}.sha1"
    
    # 将 SHA1 值写入 .sha1 文件
    echo "$sha1" > "$sha1_file"
    
    echo "Generated: $sha1_file"
done

echo "All SHA1 files have been generated."