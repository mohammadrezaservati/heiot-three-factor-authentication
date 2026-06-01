# HEIoT: A Novel Three-Factor Authentication Protocol for Enhanced Security in IoT and Next-Generation Networks

## Authors

Masoumeh Safkhani, Mohammad Reza Servati, Fatemah Rezaie

---

## Abstract

The Internet has a significant impact on contemporary society, enabling a wide range of applications, including advanced cellular networks such as 4G, 5G, and 6G. Since these communications occur over shared or open channels, ensuring secure data exchange is of critical importance, as any weakness in the communication infrastructure may compromise system reliability.

Device authentication in the Internet of Things (IoT) and user authentication in smart environments, such as smart homes, remain fundamental security challenges. As the first line of defense, authentication mechanisms must be robust, since vulnerabilities at this stage can expose the entire system to serious threats. To address these challenges, numerous authentication schemes based on cryptographic primitives, including Elliptic Curve Cryptography (ECC), have been proposed.

In this repository, we present a comprehensive security analysis of an ECC-based three-factor authentication protocol proposed by Yuan et al. Our analysis shows that the protocol is vulnerable to desynchronization, user impersonation, traceability, and insider attacks, all of which succeed with probability 1 by exploiting at most two protocol phases.

To mitigate these weaknesses, we propose an improved authentication scheme, called **HEIoT**. The proposed scheme is formally analyzed under the Real-or-Random (RoR) model to establish session-key security and is further verified using the Scyther tool. Moreover, a Python-based implementation is provided to demonstrate the practicality of the proposed protocol. Comparative results indicate that HEIoT achieves stronger security while maintaining acceptable communication, computational, and storage overhead.

---

## Index Terms

* Authentication
* Multi-Factor Authentication
* Desynchronization Attack
* Insider Adversary
* Traceability Attack
* User Impersonation Attack
* Elliptic Curve Cryptography (ECC)

---

## Repository Contents

### `heiot.py`

Main Python implementation of the proposed HEIoT authentication protocol, including:

* User registration
* Smart device registration
* Login and authentication
* Session key establishment
* Graphical user interface (GUI)
* Execution log generation

### `heiotvbenhmark.py`

Benchmarking script used to evaluate the computational performance of the complete HEIoT workflow, including:

* User registration
* Smart device registration
* Authentication and key agreement
* End-to-end protocol execution time

### `scyther.spdl.txt`

Scyther formal verification model of the proposed HEIoT protocol for validating:

* Mutual authentication
* Secrecy claims
* Session-key security
* Synchronization properties

### `README.md`

Repository documentation and usage instructions.

---

## Requirements

* Python 3.8+
* hashlib
* secrets
* sqlite3
* tkinter

All required libraries are included in the Python standard library.

---

## Running the Implementation

Run the HEIoT graphical prototype:

```bash
python heiot.py
```

The GUI provides access to:

* User Registration
* Smart Device Registration
* Login and Authentication
* Session Key Establishment
* Execution Log Visualization

---

## Running the Benchmark

Execute the benchmark script:

```bash
python heiotvbenhmark.py
```

The benchmark performs multiple independent executions of the complete protocol workflow and reports average execution times.

---

## Experimental Results

The benchmark was conducted over 1000 independent executions.

| Phase                            | Average Execution Time (ms) |
| -------------------------------- | --------------------------: |
| User Registration                |                       3.174 |
| Smart Device Registration        |                       2.935 |
| Authentication and Key Agreement |                       3.562 |
| Complete Workflow                |                       9.671 |

The results demonstrate that the proposed HEIoT protocol achieves efficient execution while maintaining the desired security properties.

---

## Formal Verification

The file `scyther.spdl.txt` contains the formal Scyther specification of the proposed protocol.

Example command:

```bash
scyther-linux scyther.spdl.txt
```

or

```bash
scyther-win.exe scyther.spdl.txt
```

depending on the operating system.

---

## License

This repository is provided for academic and research purposes.

---

## Citation

If you use this repository in your research, please cite the corresponding HEIoT paper.
