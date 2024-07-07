import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';
import typescript from '@rollup/plugin-typescript';
import pkg from './package.json' with { type: 'json' };

const name = pkg.name
	.replace(/^(@\S+\/)?(\S+)/, '$3')
	.replace(/^\w/, (m) => m.toUpperCase())
	.replace(/-\w/g, (m) => m[1].toUpperCase());

const production = !process.env.ROLLUP_WATCH;

const config = (browser = true) => {
	let output = browser ? pkg.exports['.']['browser'] : pkg.exports['.']['default'];
	return {
		input: `src/${browser ? 'browser' : 'node'}.ts`,
		output: [
			{ file: output.import, format: 'es' },
			{ file: output.require || output.default, format: 'umd', name }
		],
		plugins: [
			resolve({ preferBuiltins: !browser, browser }),
			commonjs(),
			typescript({
				sourceMap: !production,
				inlineSources: !production
			}),
			production && terser()
		],
		watch: {
			clearScreen: false
		}
	};
};
// console.log(config())
export default [config(true), config(false)];
