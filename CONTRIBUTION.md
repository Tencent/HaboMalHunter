# Contributing to HaboMalHunter
Welcome to [report Issues](https://github.com/Tencent/HaboMalHunter/issues) or [pull requests](https://github.com/Tencent/HaboMalHunter/pulls). It's recommended to read the following Contributing Guide first before contributing. 

## Issues
We use Github Issues to track public bugs and feature requests.

### Search Known Issues First
Please search the existing issues to see if any similar issue or feature request has already been filed. You should make sure your issue isn't redundant.

### Reporting New Issues
If you open an issue, the more information the better. Such as detailed description, screenshot or video of your problem, logs or code blocks for your crash.

## Pull Requests
We strongly welcome your pull request to make HaboMalHunter better. 

### Branch Management
There are three main branches here:

1. `master` branch. It is the latest (pre-)release branch.
2. `dev_*` branch. It is our stable developing branch. After full testing, `dev` will be merged to `master` branch for the next release.

Normal bugfix or feature request should be submitted to `dev` branch. After full testing, we will merge them to `master` branch for the next release. 

### Make Pull Requests
The code team will monitor all pull request, we run some code check and test on it. After all tests passed, we will accecpt this PR. But it won't merge to `master` branch at once, which have some delay.

Before submitting a pull request, please make sure the followings are done:

1. Fork the repo and create your branch from `master`.
2. Update code or documentation if you have changed APIs.
3. Add the copyright notice to the top of any new files you've added.
4. Check your code lints and checkstyles.
5. Test and test again your code.
6. Now, you can submit your pull request on `dev` branch.

## Code Style Guide

## License
By contributing to HaboMalHunter, you agree that your contributions will be licensed
under its [MIT LICENSE](https://github.com/Tencent/HaboMalHunter/blob/master/LICENSE)