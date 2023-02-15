## Automatic Static Detection of Software Security Vulnerabilities in ML Libraries: Are We There Yet?

Automatic detection of software vulnerabilities is a critical task in software security. Many static tools that can help detect security vulnerabilities have been proposed. While these static vulnerability detectors are mainly evaluated on general software projects call into question their practical effectiveness and usefulness for machine learning libraries. In this paper, we address this question by analyzing four popular and widely used static vulnerability detectors, i.e., Flawfinder, RATS, Cppcheck, and Facebook Infer on a curated dataset of software security vulnerabilities gathered from six popular ML libraries including Mlpack, Numpy, Pandas, Scipy, Pytorch, and Tensorflow with a total of 688 known security vulnerabilities. We use two novel methodologies that combine an automatic analysis of vulnerabilities with a manual validation process to determine which of these vulnerabilities each examined tool can detect. Our research provides a categorization of these tools’ capabilities to better understand the strengths and weaknesses of the tools for detecting software vulnerabilities. Overall, our study shows that static vulnerability detectors find a negligible amount of all vulnerabilities accounting for 3/590 vulnerabilities (0.5%), Cppcheck is the most effective static checker for finding software security vulnerabilities in ML libraries. Based on our observations, we further identify and discuss opportunities to make the tools more effective and practical.

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

