# Changelog

## [0.52.0](https://github.com/knqyf263/trivy/compare/v0.51.1...v0.52.0) (2024-05-27)


### Features

* Add Julia language analyzer support ([#5635](https://github.com/knqyf263/trivy/issues/5635)) ([fecafb1](https://github.com/knqyf263/trivy/commit/fecafb1fc5bb129c7485342a0775f0dd8bedd28e))
* add support for plugin index ([#6674](https://github.com/knqyf263/trivy/issues/6674)) ([26faf8f](https://github.com/knqyf263/trivy/commit/26faf8f3f04b1c5f9f81c03ffc6b2008732207e2))
* **misconf:** Add support for deprecating a check ([#6664](https://github.com/knqyf263/trivy/issues/6664)) ([88702cf](https://github.com/knqyf263/trivy/commit/88702cfd5918b093defc5b5580f7cbf16f5f2417))
* **misconf:** add Terraform 'removed' block to schema ([#6640](https://github.com/knqyf263/trivy/issues/6640)) ([b7a0a13](https://github.com/knqyf263/trivy/commit/b7a0a131a03ed49c08d3b0d481bc9284934fd6e1))
* **misconf:** register builtin Rego funcs from trivy-checks ([#6616](https://github.com/knqyf263/trivy/issues/6616)) ([7c22ee3](https://github.com/knqyf263/trivy/commit/7c22ee3df5ee51beb90e44428a99541b3d19ab98))
* **misconf:** resolve tf module from OpenTofu compatible registry ([#6743](https://github.com/knqyf263/trivy/issues/6743)) ([ac74520](https://github.com/knqyf263/trivy/commit/ac7452009bf7ca0fa8ee1de8807c792eabad405a))
* **misconf:** support symlinks inside of Helm archives ([#6621](https://github.com/knqyf263/trivy/issues/6621)) ([4eae37c](https://github.com/knqyf263/trivy/commit/4eae37c52b035b3576361c12f70d3d9517d0a73c))
* **nodejs:** add v9 pnpm lock file support ([#6617](https://github.com/knqyf263/trivy/issues/6617)) ([1e08648](https://github.com/knqyf263/trivy/commit/1e0864842e32a709941d4b4e8f521602bcee684d))
* **plugin:** specify plugin version ([#6683](https://github.com/knqyf263/trivy/issues/6683)) ([d6dc567](https://github.com/knqyf263/trivy/commit/d6dc56732babbc9d7f788c280a768d8648aa093d))
* **python:** add line number support for `requirement.txt` files ([#6729](https://github.com/knqyf263/trivy/issues/6729)) ([2bc54ad](https://github.com/knqyf263/trivy/commit/2bc54ad2752aba5de4380cb92c13b09c0abefd73))
* **report:** Include licenses and secrets filtered by rego to ModifiedFindings ([#6483](https://github.com/knqyf263/trivy/issues/6483)) ([fa3cf99](https://github.com/knqyf263/trivy/commit/fa3cf993eace4be793f85907b42365269c597b91))
* **vex:** support non-root components for products in OpenVEX ([#6728](https://github.com/knqyf263/trivy/issues/6728)) ([9515695](https://github.com/knqyf263/trivy/commit/9515695d45e9b5c20890e27e21e3ab45bfd4ce5f))


### Bug Fixes

* close APKINDEX archive file ([#6672](https://github.com/knqyf263/trivy/issues/6672)) ([5caf437](https://github.com/knqyf263/trivy/commit/5caf4377f3a7fcb1f6e1a84c67136ae62d100be3))
* close settings.xml ([#6768](https://github.com/knqyf263/trivy/issues/6768)) ([9c3e895](https://github.com/knqyf263/trivy/commit/9c3e895fcb0852c00ac03ed21338768f76b5273b))
* **conda:** add support `pip` deps for `environment.yml` files ([#6675](https://github.com/knqyf263/trivy/issues/6675)) ([150a773](https://github.com/knqyf263/trivy/commit/150a77313e980cd63797a89a03afcbc97b285f38))
* **go:** add only non-empty root modules for `gobinaries` ([#6710](https://github.com/knqyf263/trivy/issues/6710)) ([c96f2a5](https://github.com/knqyf263/trivy/commit/c96f2a5b3de820da37e14594dd537c3b0949ae9c))
* **go:** include only `.version`|`.ver` (no prefixes) ldflags for `gobinaries` ([#6705](https://github.com/knqyf263/trivy/issues/6705)) ([afb4f9d](https://github.com/knqyf263/trivy/commit/afb4f9dc4730671ba004e1734fa66422c4c86dad))
* Golang version parsing from binaries w/GOEXPERIMENT ([#6696](https://github.com/knqyf263/trivy/issues/6696)) ([696f2ae](https://github.com/knqyf263/trivy/commit/696f2ae0ecdd4f90303f41249924a09ace70dd78))
* **misconf:** don't shift ignore rule related to code ([#6708](https://github.com/knqyf263/trivy/issues/6708)) ([39a746c](https://github.com/knqyf263/trivy/commit/39a746c77837f873e87b81be40676818030f44c5))
* **misconf:** skip Rego errors with a nil location ([#6638](https://github.com/knqyf263/trivy/issues/6638)) ([a2c522d](https://github.com/knqyf263/trivy/commit/a2c522ddb229f049999c4ce74ef75a0e0f9fdc62))
* **misconf:** skip Rego errors with a nil location ([#6666](https://github.com/knqyf263/trivy/issues/6666)) ([a126e10](https://github.com/knqyf263/trivy/commit/a126e1075a44ef0e40c0dc1e214d1c5955f80242))
* node-collector high and critical cves ([#6707](https://github.com/knqyf263/trivy/issues/6707)) ([ff32deb](https://github.com/knqyf263/trivy/commit/ff32deb7bf9163c06963f557228260b3b8c161ed))
* **report:** hide empty tables if all vulns has been filtered ([#6352](https://github.com/knqyf263/trivy/issues/6352)) ([3d388d8](https://github.com/knqyf263/trivy/commit/3d388d8552ef42d4d54176309a38c1879008527b))
* use of specified context to obtain cluster name ([#6645](https://github.com/knqyf263/trivy/issues/6645)) ([39ebed4](https://github.com/knqyf263/trivy/commit/39ebed45f8c218509d264bd3f3ca548fc33d2b3a))


### Performance Improvements

* **misconf:** parse rego input once ([#6615](https://github.com/knqyf263/trivy/issues/6615)) ([67c6b1d](https://github.com/knqyf263/trivy/commit/67c6b1d473999003d682bdb42657bbf3a4a69a9c))
