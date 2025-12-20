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
Authentication, Multi-factor authentication, Desynchronization attack, Insider adversary, Traceability attack, User impersonation attack, Elliptic Curve Cryptography (ECC)

---

## Repository Contents
- `implementation/`  
  Python implementation of the proposed HEIoT authentication protocol.
- `security-analysis/`  
  Detailed cryptanalysis of the original scheme and formal security proofs under the RoR model.
- `scyther/`  
  Formal verification files for the HEIoT protocol using the Scyther tool.
- `results/`  
  Performance and security comparison results.

---

## Requirements
- Python 3.8 or later
- hashlib, secrets (standard Python libraries)

---

## Running the Implementation
To run the HEIoT protocol implementation:

```bash
cd implementation
python heiot.py
