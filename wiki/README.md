# Wiki 源文件

此目录是 [GitHub Wiki](https://github.com/lonelam/subconverter-rs/wiki) 的源文件，随代码一起版本化和评审。

修改文档请编辑本目录下的页面，然后同步到 wiki 仓库（`git@github.com:lonelam/subconverter-rs.wiki.git`）。同步时需把页面间链接的 `.md` 后缀去掉（GitHub Wiki 的页面链接不带扩展名），例如：

```bash
for f in Home Getting-Started HTTP-API Protocols-and-Targets Advanced-Usage Library-and-WASM; do
  perl -pe 's/\]\((Home|Getting-Started|HTTP-API|Protocols-and-Targets|Advanced-Usage|Library-and-WASM)\.md(#[^)]*)?\)/]($1$2)/g' \
    wiki/$f.md > ../subconverter-rs.wiki/$f.md
done
```

侧边栏导航维护在 wiki 仓库的 `_Sidebar.md`。
