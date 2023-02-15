## Automatic Static Detection of Software Security Vulnerabilities in ML Libraries: Are We There Yet?

Automatic detection of software vulnerabilities is a critical task in software security. Many static tools that can help detect security vulnerabilities have been proposed. While these static vulnerability detectors are mainly evaluated on general software projects call into question their practical effectiveness and usefulness for machine learning libraries. In this paper, we address this question by analyzing six popular and widely used static vulnerability detectors, i.e., Flawfinder, RATS, Cppcheck, Facebook Infer, Clang, and Clang-tidy on a curated dataset of software security vulnerabilities gathered from four popular machine learning libraries including Mlpack, MXNet, PyTorch, and TensorFlow with a total of 410 known security vulnerabilities. Our research provides a categorization of these tools’ capabilities to better understand the strengths and weaknesses of the tools for detecting software vulnerabilities in machine learning libraries. Overall, our study shows that static vulnerability detectors find a negligible amount of all vulnerabilities accounting for 4/410 vulnerabilities (0.009\%), Flawfinder and RATS are the most effective static checker for finding software security vulnerabilities in machine learning libraries. Based on our observations, we further identify and discuss opportunities to make the tools more effective and practical. 

## Steps to reproduce the results

In order to run the scripts in the repository and replicate the results, you need to have the following packages installed:

```
panads 1.3.5
numpy 1.22.3
pydriller 1.15.5
requests 2.26.0
git 3.1.18
```
The vulnerability fixing commits for the studied ML libraries can be found under the ```data/vic_vfs``` directory. But, in order to reproduce the commits, please run the following script:

