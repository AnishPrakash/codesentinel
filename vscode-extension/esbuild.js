// Bundles src/extension.ts and everything it imports into a single out/extension.js.
//
// Why bundle at all: `tsc` emits one .js per .ts plus a node_modules tree the
// .vsix would have to carry. esbuild produces one file, which makes the package
// small and the load fast. `vscode` is external because the editor provides it
// at runtime - bundling it would ship a second copy that cannot work.
const esbuild = require('esbuild');

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

const options = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'out/extension.js',
  external: ['vscode'],
  format: 'cjs',
  platform: 'node',
  target: 'node18',
  sourcemap: !production,
  minify: production,
  logLevel: 'info',
};

async function main() {
  if (watch) {
    const ctx = await esbuild.context(options);
    await ctx.watch();
    console.log('watching...');
  } else {
    await esbuild.build(options);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
