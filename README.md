<div align="center">

# 🔩 Awesome Bare Metal Hacking

> A **deeply curated** list of resources for bare metal security research -  
> firmware reversing · exploitation · fuzzing · fault injection · debug interface attacks · secure boot bypasses · TrustZone/TEE · side-channel analysis

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
![Last Updated](https://img.shields.io/badge/last%20updated-2026-blue)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

</div>

---

## 📌 What is Bare Metal Hacking?

**Bare metal** refers to embedded systems that run **directly on hardware with no OS layer** - ARM Cortex-M/R/A, RISC-V, AVR, MIPS MCUs found in IoT devices, industrial controllers, medical hardware, automotive ECUs, satellites, and smart cards.

Security research in this space involves:

- 🔍 **Firmware extraction** via JTAG/SWD, UART, flash chip-off, and rowhammer
- 🔬 **Reverse engineering** of stripped binaries with no symbols, no RTOS, no libc
- 💥 **Exploitation** - stack overflows, ROP chains, Function-Oriented Programming (FOP)
- ⚡ **Fault injection** - voltage glitching, clock glitching, EM fault injection (EMFI)
- 🔐 **Secure boot bypass** - readout protection (RDP) bypass, TrustZone attacks, TEE exploitation
- 🤖 **Bare metal fuzzing** - MMIO modeling, rehosting, peripheral emulation with QEMU/Unicorn
- 📡 **Debug interface attacks** - JTAG/SWD unlocking, OpenOCD exploitation

---

## 📚 Table of Contents

- [🎬 YouTube Videos & Channels](#-youtube-videos--channels)
  - [Channels to Follow](#channels-to-follow)
  - [Must-Watch Videos](#must-watch-videos)
- [🎤 Technical Talks & Conference Presentations](#-technical-talks--conference-presentations)
  - [DEF CON](#def-con)
  - [Black Hat](#black-hat)
  - [hardwear.io](#hardweario)
  - [BSides & Other Conferences](#bsides--other-conferences)
  - [OSFC (Open Source Firmware Conference)](#osfc-open-source-firmware-conference)
- [📝 Research Blogs & Technical Write-ups](#-research-blogs--technical-write-ups)
  - [Firmware Reverse Engineering](#firmware-reverse-engineering)
  - [Debug Interface Attacks (JTAG / SWD / UART)](#debug-interface-attacks-jtag--swd--uart)
  - [Readout Protection & Glitch Attacks](#readout-protection--glitch-attacks)
  - [Secure Boot, TrustZone & TEE](#secure-boot-trustzone--tee)
  - [Firmware Fuzzing & Emulation](#firmware-fuzzing--emulation)
  - [Bare Metal Cloud Security](#bare-metal-cloud-security)
- [📄 Research Papers](#-research-papers)
  - [Surveys & SoKs](#surveys--soks)
  - [Fuzzing & Emulation](#fuzzing--emulation)
  - [Exploitation & Memory Safety](#exploitation--memory-safety)
  - [TrustZone & TEE](#trustzone--tee)
- [🛠 Tools](#-tools)
  - [Reverse Engineering](#reverse-engineering)
  - [Firmware Analysis & Extraction](#firmware-analysis--extraction)
  - [Emulation & Rehosting](#emulation--rehosting)
  - [Fuzzing Frameworks](#fuzzing-frameworks)
  - [Debug Interface (JTAG / SWD / UART)](#debug-interface-jtag--swd--uart-1)
  - [Fault Injection & Side-Channel](#fault-injection--side-channel)
  - [Secure Boot & TEE Frameworks](#secure-boot--tee-frameworks)
- [📦 GitHub Repositories](#-github-repositories)
  - [Awesome Lists & Meta-Collections](#awesome-lists--meta-collections)
  - [Exploit & Research Codebases](#exploit--research-codebases)
  - [Bare Metal Frameworks](#bare-metal-frameworks)
  - [Practice & CTF Targets](#practice--ctf-targets)
- [🏛 OWASP Projects](#-owasp-projects)
- [📖 Books](#-books)
- [🎓 Courses & Trainings](#-courses--trainings)
- [🎮 CTF Challenges & Practice](#-ctf-challenges--practice)
- [🤝 Contributing](#-contributing)

---

## 🎬 YouTube Videos & Channels

### Channels to Follow

> These channels consistently publish bare metal security, firmware RE, hardware hacking, and embedded exploitation content.

| Channel | Focus | Link |
|---------|-------|------|
| **stacksmashing** | Bare metal ARM RE, Ghidra, glitching, Flipper Zero internals | [YouTube](https://www.youtube.com/@stacksmashing) |
| **Colin O'Flynn / NewAE Technology** | ChipWhisperer, power analysis, voltage glitching, fault injection | [YouTube](https://www.youtube.com/@newaetech) |
| **LiveOverflow** | Binary exploitation, RE, CTF - great ARM exploitation series | [YouTube](https://www.youtube.com/@LiveOverflow) |
| **Bare Metal Cyber** | Educational embedded cybersecurity audio and video courses | [YouTube](https://www.youtube.com/@Bare-Metal-Cyber) |
| **Matt Brown / Brown Fine Security** | ARM binary exploitation, IoT pentesting, bare metal BOF | [YouTube](https://www.youtube.com/@BrownFineSecurity) |
| **RECESSIM** | Fault injection on automotive MCUs, smart meter RE | [YouTube](https://www.youtube.com/c/RECESSIM) |
| **Hardwear.io** | Hardware security conference talks; fault injection, JTAG, glitching | [YouTube](https://www.youtube.com/@hardwear_io) |

---

### Must-Watch Videos

#### 🔴 Bare Metal Reverse Engineering

| Title | Channel | Year | What You'll Learn |
|-------|---------|------|-------------------|
| [Bare Metal Reverse Engineering](https://www.youtube.com/watch?v=zfxKbsLKb3E) | SolaSec @ DEF CON 33 | 2025 | Full methodology for RE of real-time bare metal ARM firmware with no RTOS |
| [Bare-metal ARM firmware RE with Ghidra and SVD-Loader](https://www.youtube.com/watch?v=q4CxE5P6RUE) | stacksmashing | 2020 | Loading ARM Cortex-M binaries into Ghidra, CMSIS-SVD peripheral mapping, crackme walkthrough |
| [Analyzing Bare Metal Binaries in Ghidra (Demo)](https://blog.attify.com/analyzing-bare-metal-firmware-binaries-in-ghidra/) | Attify | 2021 | STM32 binary: setting load address, defining memory segments, finding main() |
| [Intro to Firmware Analysis with QEMU and Ghidra](https://www.youtube.com/watch?v=50lFwNvHbDs) | Various | 2024 | End-to-end: extract firmware → emulate in QEMU → static analysis in Ghidra |
| [WHY2025 - Bare Metal Programming From the Ground Up](https://www.youtube.com/watch?v=lH-6OLzdbkI) | WHY2025 Conference | 2025 | What happens from power-on to your first instruction - vectors, startup, peripherals |

#### ⚡ Fault Injection & Glitching

| Title | Channel | Year | What You'll Learn |
|-------|---------|------|-------------------|
| [The Cheapskate Revolution: Hardware Attacks from Millions to Tens of Dollars](https://www.youtube.com/watch?v=Rn_OD9N77cA) | Colin O'Flynn @ hardwear.io USA 2021 | 2021 | History and democratization of SCA, VFI, EMFI - $10 attacks on brand new devices |
| [Power Analysis and Glitch Attacks with ChipWhisperer](https://www.youtube.com/watch?v=8WtoB7fYVig) | Colin O'Flynn @ Pentester Academy | 2017 | AES key recovery via power analysis, bootloader bypass with clock glitching |
| [Clock Glitch Attack: Bypassing Password Check](https://www.youtube.com/watch?v=Ruphw9-8JWE) | Colin O'Flynn / NewAE | 2014 | Live demo: clock glitch skips an if-statement, bypasses a password check |
| [Power Analysis and Clock Glitching - REcon 2014](https://www.youtube.com/watch?v=RivTttNRJ8k) | Colin O'Flynn @ REcon | 2014 | ChipWhisperer hardware architecture; target + probe circuit; attack orchestration demo |
| [ChipWhisperer Demo: Hardware Hacking & FPGAs](https://www.youtube.com/watch?v=Hl-2UQs20BA) | Teardown Session | 2022 | ChipWhisperer Husky internals, low-risk CIC, live fault injection demo + FPGA integration |

#### 💥 Exploitation

| Title | Channel | Year | What You'll Learn |
|-------|---------|------|-------------------|
| [Metal-as-a-Disservice: Exploiting Bare Metal Clouds](https://www.youtube.com/watch?v=EtGhHCr3VLE) | Bill Demirkapi @ DEF CON 33 | 2025 | Hijacking bare metal provisioning, persistent UEFI firmware implants, ML workload compromise |
| [UEFI Exploitation for the Masses](https://www.youtube.com/watch?v=CxqNgjMZAbk) | Shkatov & Michael @ DEF CON 26 | 2018 | SMM backdoors, BIOS exploitation, Intel hardware debug on ARM targets |
| [Breaking Firmware Trust From Pre-EFI](https://www.youtube.com/watch?v=Z81s7UIiwmI) | Alex Ermolov et al. @ Black Hat 2022 | 2022 | Exploiting Intel PPAM and SMI Transfer Monitor - first public offensive research |
| [ARM Assembly and Buffer Overflows - Intro to ARM Binary Exploitation](https://www.youtube.com/watch?v=sfcJrdl0lq0) | Brown Fine Security | 2025 | ARM assembly primer, stack layout, BOF on bare metal Cortex-M with Binary Ninja |
| [More Buffer Overflows - ARM Exploitation](https://www.youtube.com/watch?v=WVUTi1gOgS4) | Brown Fine Security | 2025 | Continued series: building ROP chains on ARM bare metal, exploit delivery |
| [Binary Exploitation / Memory Corruption Playlist](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) | LiveOverflow | 2016–2025 | 40+ videos: from format strings to heap exploitation; includes ARM segments |

#### 🔩 Hardware Hacking & Embedded Systems

| Title | Channel | Year | What You'll Learn |
|-------|---------|------|-------------------|
| [A Short Trip to Baremetal Hardware Hacking](https://www.youtube.com/watch?v=96OavFvu2y8) | Javier Tallón @ CyberCamp 2018 | 2018 | Chip-off firmware extraction, readout protection bypass, full RE walkthrough |
| [Hacking Embedded Devices - Black Box to UID 0](https://www.youtube.com/watch?v=Md39nIlMo5k) | Zezadas & David @ BSides Lisbon 2023 | 2024 | Root shell on video converter: decompile APK → find vuln → exploit file path traversal → RCE |
| [Embedded Security: Roots-of-Trust, Secure Boot](https://www.youtube.com/watch?v=7YV1mEm6MLo) | Embedded Security Talk | 2023 | Threat modelling, roots-of-trust, boot chain integrity, TPM attestation for bare metal |
| [Omer Kilic - Bare Metal from a Hardware Perspective](https://www.youtube.com/watch?v=_4FItSzedBk) | Code Mesh | 2019 | Embedded frameworks, build systems, bare metal vs RTOS architecture tradeoffs |
| [Breaking In to Break Things: Practical Paths to Hardware Hacking](https://www.youtube.com/watch?v=rEQgteBEfpk) | RECESSIM @ IoT Security Podcast | 2025 | Low-cost fault injection on automotive MCUs, smart meter RE, community + mindset |

---

## 🎤 Technical Talks & Conference Presentations

### DEF CON

| Year | Talk Title | Speaker(s) | Key Topics | Link |
|------|-----------|-----------|------------|------|
| 2025 (DC33) | **Bare Metal Reverse Engineering** | SolaSec | ARM Cortex-M RE methodology, Ghidra, MMIO | [YouTube](https://www.youtube.com/watch?v=zfxKbsLKb3E) |
| 2025 (DC33) | **Metal-as-a-Disservice: Exploiting Legacy Flaws in Cutting Edge Clouds** | Bill Demirkapi | Bare metal cloud provisioning hijack, firmware implants, ML workload compromise | [YouTube](https://www.youtube.com/watch?v=EtGhHCr3VLE) |
| 2018 (DC26) | **UEFI Exploitation for the Masses** | Dmitry Shkatov, Jesse Michael | BIOS/UEFI attack surface, SMM backdoors, Intel HW debug | [YouTube](https://www.youtube.com/watch?v=CxqNgjMZAbk) |

### Black Hat

| Year | Talk Title | Speaker(s) | Key Topics | Link |
|------|-----------|-----------|------------|------|
| 2022 | **Breaking Firmware Trust From Pre-EFI: Exploiting Early Boot Phases** | Alex Ermolov, Alex Matrosov et al. | Intel PPAM, SMI Transfer Monitor, pre-EFI code execution | [YouTube](https://www.youtube.com/watch?v=Z81s7UIiwmI) |
| 2018 | **Hacking Firmware & Hardware: Software Exploitation via Hardware** | Training | Bare metal exploit development, JTAG, SWD, firmware extraction | [Black Hat](https://www.blackhat.com/us-18/training/hacking-firmware-and-hardware-software-exploitation-via-hardware-exploitation.html) |
| 2024 | **Advanced Embedded & Firmware Security Training** | Multiple | Full-spectrum firmware security training | [Schedule](https://blackhat.com/us-24/training/schedule/) |

### hardwear.io

| Year | Talk Title | Speaker | Key Topics | Link |
|------|-----------|--------|------------|------|
| 2021 | **The Cheapskate Revolution: Hardware Attacks from Millions to Tens of Dollars** | Colin O'Flynn | History of SCA/VFI/EMFI, democratization, $10 glitching tools | [YouTube](https://www.youtube.com/watch?v=Rn_OD9N77cA) |

### BSides & Other Conferences

| Year | Talk Title | Speaker(s) | Venue | Link |
|------|-----------|-----------|-------|------|
| 2024 | **Hacking Embedded Devices - Black Box to UID 0** | Zezadas & David Silva | BSides Lisbon 2023 | [YouTube](https://www.youtube.com/watch?v=Md39nIlMo5k) |
| 2018 | **A Short Trip to the Baremetal Hardware Hacking** | Javier Tallón | CyberCamp 2018 | [YouTube](https://www.youtube.com/watch?v=96OavFvu2y8) |
| 2014 | **Power Analysis and Clock Glitching with ChipWhisperer** | Colin O'Flynn | REcon 2014 | [YouTube](https://www.youtube.com/watch?v=RivTttNRJ8k) |

### OSFC (Open Source Firmware Conference)

| Year | Notes | Link |
|------|-------|------|
| 2024 | TamaGo author Andrea Barisani + open source firmware ecosystem talks | [osfc.io](https://talks.osfc.io/osfc-2024/speaker/) |

---

## 📝 Research Blogs & Technical Write-ups

### Firmware Reverse Engineering

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [Analyzing Bare Metal Firmware Binaries in Ghidra](https://blog.attify.com/analyzing-bare-metal-firmware-binaries-in-ghidra/) | Attify Blog | Practical: set load address for STM32, define memory segments, locate `main()`, identify peripherals using SVD |
| [Bare-metal ARM RE with Ghidra and SVD-Loader](https://www.youtube.com/watch?v=q4CxE5P6RUE) | stacksmashing | How to use CMSIS-SVD files to auto-annotate 800+ peripherals in Ghidra for any ARM MCU |
| [Demystifying Arm Cortex-M33 Bare Metal: Startup](https://metebalci.com/blog/demystifying-arm-cortex-m33-bare-metal-startup/) | Mete Balci | Zero-to-main deep dive: vector table, startup code, stack init, clock config on Cortex-M33 |
| [How to Do Firmware Analysis: Tools, Tips, and Tricks](https://www.pentestpartners.com/security-blog/how-to-do-firmware-analysis-tools-tips-and-tricks/) | Pentest Partners | Methodology: binwalk extraction → Ghidra RE → EMBA scanning → dynamic testing |
| [Firmware Analysis Guide: Detect & Fix Embedded Vulnerabilities](https://bugprove.com) | BugProve | Static analysis pipeline, CVE matching, SBOM generation for bare metal blobs |
| [Embedded Systems Engineering Roadmap](https://github.com/m3y54m/Embedded-Engineering-Roadmap) | m3y54m | Full learning path: from bare metal programming basics to hardware security |

### Debug Interface Attacks (JTAG / SWD / UART)

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [IoT Security Part 18: Hardware Attack Surface – JTAG, SWD](https://payatu.com/blog/hardware-attack-surface-jtag-swd/) | Payatu | In-depth: JTAG TAP state machine, SWD DAP architecture, JTAGulator usage, buffer overflow via debug port leading to RCE |
| [IoT Security Masterclass: JTAG & SWD](https://payatu.com/masterclass/iot-security-part-18-101-hardware-attack-surface-jtag-swd/) | Payatu Masterclass | Extended practical tutorial on pin identification (JTAGulator), OpenOCD setup, debug-assisted firmware dump |
| [Hacking Hardware Part 7: UART, JTAG and SWD Port Vulnerabilities](https://hackyourmom.com/en/osvita/english-chastyna-7-zlom-aparatnoyi-chastyny-systemy-uraznosti-portiv-uart-jtag-i-swd/) | HackYourMom | Tool comparison: Bus Blaster, Black Magic Probe, J-Link, ST-Link; when to use UART vs JTAG |
| [For hardware hacking, which do you use most: UART or JTAG?](https://www.reddit.com/r/hardwarehacking/comments/1jfq1wg/for_hardware_hacking_which_do_you_use_most_uart/) | r/hardwarehacking | Community discussion: real-world trade-offs; JTAG preferred for memory dumps, UART for shell access |

### Readout Protection & Glitch Attacks

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [Glitching STM32 Read Out Protection with Voltage Fault Injection](https://www.anvilsecure.com/blog/glitching-stm32-read-out-protection-with-voltage-fault-injection.html) | Anvil Secure (2025) | VFI on STM32F401CC to bypass RDP Level 1; custom glitcher hardware, timing window discovery, full firmware dump |
| [nRF51 Readback Protection (RBPCONF) Bypass](https://iamalch3mist.github.io/posts/nrf51_code_readout_bypass/) | IamAlch3mist (2024) | Load Instruction Exploitation on nRF51822 Cortex-M0 - $10 dev module, no special hardware needed |
| [Bypassing Readout Protection in Nordic Semiconductor MCUs](https://www.emproof.com/bypassing-readout-protection-in-nordic-semiconductor-microcontrollers/) | Emproof (2024) | Complete nRF51 DK attack walk-through; RBPCONF register analysis, protection bypass methodology |
| [STM32 Readout Protection Cracked Discussion](https://community.st.com/t5/stm32-mcus-security/readout-protection-cracked-on-stm32/td-p/387997) | ST Community | Community analysis of STM32 RDP bypass research and vendor response |

### Secure Boot, TrustZone & TEE

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [Implementing Secure Boot and TEEs on Bare Metal](https://intechhouse.com/blog/bare-metal-security-implementing-secure-boot-and-trusted-execution-environments-tee/) | IntechHouse (Feb 2026) | Layered secure boot architecture, ARM TrustZone integration, TEE provisioning for resource-constrained MCUs |
| [USB Armory / TamaGo Security Features](https://reversec.com/usb-armory/) | reversec.com | RPMB replay protection, bare metal Go TEE (GoTEE), no C runtime dependency, secure storage architecture |
| [Understanding TrustZone Vulnerabilities (SoK)](https://oaklandsok.github.io/papers/cerdeira2020.pdf) | IEEE S&P 2020 | Taxonomy of 80+ CVEs across TEE implementations; privilege escalation, confused deputy, memory disclosure |

### Firmware Fuzzing & Emulation

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [Fuzzing Device Emulation in QEMU](https://research.redhat.com/blog/research_project/fuzzing-device-emulation-in-qemu/) | Red Hat Research | Coverage-guided fuzzing of QEMU virtual devices; structure-aware fuzz targets for bare metal emulation |
| [Fuzzware: Using Precise MMIO Modeling for Effective Firmware Fuzzing](https://fuzzware.io) | fuzzware.io | Auto-models MMIO access patterns for Cortex-M3/M4; finds 0-days in real-world bare metal images |
| [SAFIREFUZZ: Same-Architecture Firmware Rehosting](https://github.com/pr0me/SAFIREFUZZ) | pr0me | Near-native throughput fuzzing; no emulation overhead by running firmware natively with thin shim |

### Bare Metal Cloud Security

| Title | Author / Source | Description |
|-------|----------------|-------------|
| [Revisiting Bare Metal Server Security in the Age of AI](https://eclypsium.com/blog/revisiting-bare-metal-server-security-in-the-age-of-ai/) | Eclypsium (Jul 2025) | Hardware rootkits persisting across tenant transitions, TPM 2.0 attestation, secure boot gaps in AI cloud infra |

---

## 📄 Research Papers

### Surveys & SoKs

| Paper | Venue | Year | Abstract |
|-------|-------|------|----------|
| [SoK: Where's the "up"?! Comprehensive Bottom-up Study on ARM Cortex-M Security](https://arxiv.org/abs/2401.15289) | USENIX / arXiv | 2024 | Analysis of 1,797 real-world bare metal firmware images; maps hardware security feature adoption, bug taxonomy, attack prevalence |
| [Bare-Metal Firmware Fuzzing: A Survey of Techniques and Tools](https://ieeexplore.ieee.org/iel8/6287639/10820123/11020638.pdf) | IEEE | 2025 | Comprehensive survey of emulation-based bare metal fuzzing (HALucinator, P2IM, Fuzzware, SAFIREFUZZ, PartEmu) |

### Fuzzing & Emulation

| Paper | Venue | Year | Abstract |
|-------|-------|------|----------|
| [P2IM: Scalable and Hardware-independent Firmware Testing via Peripheral Interface Modeling](https://github.com/RiS3-Lab/p2im) | USENIX Security | 2020 | Models MCU peripheral interfaces automatically; enables firmware fuzzing without hardware using QEMU |
| [HALucinator: Firmware Re-hosting Through Abstraction Layer Emulation](https://github.com/ucsb-seclab/hal-fuzz) | USENIX Security | 2020 | Replaces hardware abstraction layer functions at runtime to rehost and fuzz closed-source blob firmware |
| [SAFIREFUZZ: Same-Architecture Firmware Rehosting and Fuzzing](https://github.com/pr0me/SAFIREFUZZ) | USENIX Security | 2023 | Near-native throughput rehosting using thin binary shim; outperforms QEMU-based approaches by 100x |
| [Fuzzware: Using Precise MMIO Modeling for Effective Firmware Fuzzing](https://fuzzware.io) | USENIX Security | 2022 | Automatically infers MMIO peripheral model; finds bugs in 7 real-world Cortex-M3/M4 firmware images |
| [FANDEMIC: Firmware Attack Construction and Deployment on Power Management ICs](https://www.ndss-symposium.org/wp-content/uploads/2022-349-paper.pdf) | NDSS | 2022 | Reverse engineering bare metal IoT firmware targeting PMIC chips; persistent firmware attack |
| [Binary-Agnostic Fault Injection to Evaluate Cosmic Radiation Impact](https://mschloegel.me/paper/willbold2025radsim.pdf) | 2025 | 2025 | Bare metal Cortex-M satellite firmware simulation; LLVM-based mitigation evaluation |

### Exploitation & Memory Safety

| Paper | Venue | Year | Abstract |
|-------|-------|------|----------|
| [Function-Oriented Programming Attacks on ARM Cortex-M Processors](https://ieeexplore.ieee.org/iel8/6287639/10820123/11164498.pdf) | IEEE | 2024 | Novel code-reuse attack exploiting function-level gadgets in MPU-protected bare metal firmware |
| [Update If You Dare: Demystifying Bare-Metal Device Firmware Updates](https://www.computer.org/csdl/journal/tq/2025/03/10758829/221BBxel1pm) | IEEE Trans. on SW Eng. | 2025 | Systematic analysis of firmware update mechanisms on ARM Cortex-M; downgrade attacks, signature bypass |
| [Retrofitting XoM for Stripped Binaries without Embedded Data](https://www.ndss-symposium.org/wp-content/uploads/2025-825-paper.pdf) | NDSS | 2025 | Enforcing execute-only memory on stripped bare metal ARM binaries to prevent code disclosure |

### TrustZone & TEE

| Paper | Venue | Year | Abstract |
|-------|-------|------|----------|
| [REZONE: Disarming TrustZone with TEE Privilege Reduction](https://www.usenix.org/system/files/sec22fall_cerdeira.pdf) | USENIX Security | 2022 | Shows that over-privileged TEEs are exploitable; proposes privilege separation in TrustZone |
| [Understanding Prevailing Security Vulnerabilities in TrustZone TEEs](https://oaklandsok.github.io/papers/cerdeira2020.pdf) | IEEE S&P | 2020 | Taxonomy of 80+ CVEs across OP-TEE, QSEE, iTrustee; confused deputy, TOCTOU, memory disclosure |
| [Towards Trustworthy TrustZone-Assisted TEEs (PhD Thesis)](https://syssec.dpss.inesc-id.pt/papers/cerdeira_phd24.pdf) | INESC-ID | 2024 | Comprehensive formal analysis of TrustZone security properties and architectural flaws |

---

## 🛠 Tools

### Reverse Engineering

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **Ghidra** | NSA's free RE framework with ARM Cortex-M support | Must use with SVD-Loader for bare metal | [ghidra-sre.org](https://ghidra-sre.org) |
| **SVD-Loader for Ghidra** | Auto-maps 800+ hardware peripherals from CMSIS-SVD into Ghidra | Essential for bare metal RE | [GitHub](https://github.com/leveldown-security/SVD-Loader-Ghidra) |
| **Radare2** | Powerful CLI RE framework; ARM, THUMB, RISC-V support | Good for scripting and automation | [GitHub](https://github.com/radareorg/radare2) |
| **Rizin** | Fork of Radare2 with cleaner API; bare metal ARM support | Preferred by many researchers | [GitHub](https://github.com/rizinorg/rizin) |
| **Binary Ninja** | Commercial RE platform; excellent ARM bare metal lifting | Used in Matt Brown's ARM exploitation series | [binary.ninja](https://binary.ninja) |
| **IDA Pro + ARM Plugin** | Industry-standard disassembler; best THUMB2 support | Expensive but gold standard | [hex-rays.com](https://hex-rays.com) |
| **angr** | Python symbolic execution framework; models MCU firmware | Use with avatar2 for bare metal | [GitHub](https://github.com/angr/angr) |
| **Capstone** | Multi-arch disassembly engine (ARM, THUMB, RISC-V, MIPS) | Used in custom tooling and scripts | [GitHub](https://github.com/capstone-engine/capstone) |
| **cwe_checker** | Static vulnerability checker with experimental bare metal support | Runs on stripped binaries, CBMC-based | [GitHub](https://github.com/fkie-cad/cwe_checker) |
| **CMSIS-SVD Data** | Database of 1,000+ ARM MCU peripheral definitions (STM32, Nordic, etc.) | Used with SVD-Loader | [GitHub](https://github.com/posborne/cmsis-svd) |

### Firmware Analysis & Extraction

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **Binwalk v3** | Firmware analysis and extraction tool (Rust rewrite) | Identify/extract compressed filesystems, certs, keys | [GitHub](https://github.com/ReFirmLabs/binwalk) |
| **EMBA** | Full-featured automated firmware security scanner with SBOM | CISA SBOM compliance, CVE matching | [GitHub](https://github.com/e-m-b-a/emba) |
| **EMBArk** | Docker-based web UI for EMBA | Easy deployment for team use | [GitHub](https://github.com/e-m-b-a/embark) |
| **FACT (Firmware Analysis & Comparison Tool)** | Web-based firmware analysis with plugin architecture | Diff between firmware versions | [GitHub](https://github.com/fkie-cad/FACT_core) |
| **Firmwalker** | Script searching extracted firmware for sensitive data | Finds hardcoded passwords, keys, certs | [GitHub](https://github.com/craigz28/firmwalker) |
| **Firmadyne** | Linux-based firmware emulation and dynamic analysis | Works on MIPS/ARM Linux firmwares | [GitHub](https://github.com/firmadyne/firmadyne) |
| **UEFI Firmware Parser** | Python tool for parsing and extracting UEFI/BIOS images | Extract modules, sections, certificates | [GitHub](https://github.com/theopolis/uefi-firmware-parser) |
| **XGecu Universal Programmer** | Hardware: chip-off flash reader supporting 13,000+ chips | Essential for direct flash extraction | [xgecu.com](http://www.xgecu.com) |

### Emulation & Rehosting

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **P2IM** | Peripheral interface modeling for bare metal firmware on QEMU | USENIX Security '20 paper | [GitHub](https://github.com/RiS3-Lab/p2im) |
| **HALucinator / HAL-Fuzz** | High-level emulation (HLE) of hardware abstraction layers | Handles blob firmware without source | [GitHub](https://github.com/ucsb-seclab/hal-fuzz) |
| **SAFIREFUZZ** | Near-native ARM Cortex-M rehosting + fuzzing | 100x throughput vs QEMU | [GitHub](https://github.com/pr0me/SAFIREFUZZ) |
| **QEMU** | Full system emulator; ARM (Cortex-M, A), RISC-V, MIPS | Backbone of most bare metal emulation | [qemu.org](https://www.qemu.org) |
| **Unicorn Engine** | Lightweight CPU emulator for binary analysis and emulation | Single-step execution, snapshot/restore | [GitHub](https://github.com/unicorn-engine/unicorn) |
| **Avatar²** | Multi-target orchestration (combines JTAG debugger + emulator) | Bridges real hardware and emulator for analysis | [GitHub](https://github.com/avatartwo/avatar2) |
| **PartEmu** | TrustZone partition emulation for Cortex-A bare metal TEE analysis | Research tool for TEE RE | Academic |

### Fuzzing Frameworks

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **Fuzzware** | Self-configuring fuzzer for ARM Cortex-M3/M4 bare metal images | Auto-models MMIO; finds real 0-days | [GitHub](https://github.com/fuzzware-fuzzer/fuzzware) |
| **Fuzzware Pipeline** | Job distribution layer for Fuzzware multi-instance parallel fuzzing | Needed for large-scale campaigns | [GitHub](https://github.com/fuzzware-fuzzer/fuzzware-pipeline) |
| **Fuzzware Emulator** | AFL forkserver-based QEMU emulation component | Core fuzzing engine | [GitHub](https://github.com/fuzzware-fuzzer/fuzzware-emulator) |
| **HAL-Fuzz** | AFL-based fuzzer using HALucinator for hardware-less firmware testing | Works on ARM blob binaries | [GitHub](https://github.com/ucsb-seclab/hal-fuzz) |
| **SAFIREFUZZ** | USENIX '23: near-native throughput fuzzer with thin binary shim | Best throughput of all rehosting fuzzers | [GitHub](https://github.com/pr0me/SAFIREFUZZ) |
| **AFL++** | State-of-the-art coverage-guided fuzzer with QEMU mode | QEMU mode for bare metal emulation | [GitHub](https://github.com/AFLplusplus/AFLplusplus) |
| **LibAFL** | Rust fuzzing library; build custom fuzzers for embedded targets | More flexible than AFL++ for custom targets | [GitHub](https://github.com/AFLplusplus/LibAFL) |

### Debug Interface (JTAG / SWD / UART)

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **OpenOCD** | Open On-Chip Debugger; JTAG/SWD for most ARM MCUs | Free; combine with GDB for debug | [openocd.org](https://openocd.org) |
| **pyOCD** | Python-based CMSIS-DAP/SWD debugger for ARM Cortex-M | Scriptable; great for automation | [GitHub](https://github.com/pyocd/pyOCD) |
| **Black Magic Probe** | Open source JTAG/SWD debug probe with built-in GDB server | No OpenOCD needed; runs bare metal | [GitHub](https://github.com/blackmagic-debug/blackmagic) |
| **JLink / JLinkExe** | SEGGER professional JTAG/SWD probe; fastest speeds | Best for production-grade targets | [SEGGER](https://www.segger.com/products/debug-probes/j-link/) |
| **JTAGulator** | Dedicated tool for identifying JTAG, SWD, and UART pins on PCB | Adjustable voltage; essential for PCB recon | [GitHub](https://github.com/grandideastudio/jtagulator) |
| **Bus Pirate** | Multi-protocol tool (JTAG, SWD, I2C, SPI, UART) | Budget-friendly Swiss Army knife | [dangerous-things.com](http://dangerousprototypes.com/docs/Bus_Pirate) |
| **UrJTAG** | Universal JTAG library and boundary-scan flash tool | Good for custom JTAG device support | [urjtag.org](http://urjtag.org) |
| **GDB + gdb-multiarch** | GNU Debugger with ARM bare metal remote debug support | via OpenOCD or Black Magic Probe | [gnu.org](https://www.gnu.org/software/gdb/) |

### Fault Injection & Side-Channel

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **ChipWhisperer** | The gold standard for power analysis and voltage/clock glitching | Open source; Python API | [GitHub](https://github.com/newaetech/chipwhisperer) |
| **ChipWhisperer Husky** | Latest CW hardware with FPGA; higher sample rates for advanced attacks | Best for AES and RSA side-channel | [NewAE](https://www.newae.com) |
| **PicoEMP** | Low-cost EM fault injection tool on RP2040 | ~$20 DIY EMFI tool | [GitHub](https://github.com/newaetech/picoemp) |
| **GreatFET One** | USB-connected hardware tool for fault injection and side channel | NFC, USB, and hardware RE | [GitHub](https://github.com/greatscottgadgets/greatfet) |
| **faultier** | Open-source voltage glitching framework by stacksmashing | Designed for repeatability | [GitHub](https://github.com/stacksmashing/faultier) |
| **Pico-RDP-Glitcher** | RP2040-based STM32 RDP bypass glitcher | Community build; < $5 | Community |
| **Riscure Inspector** | Commercial SCA/FI platform; used in certification labs | Industry standard for EAL5+ | [riscure.com](https://www.riscure.com) |
| **SideChannelMarvels** | Academic SCA tools: Daredevil (CPA), Jlsca, Scared | Python/Julia analysis toolkits | [GitHub](https://github.com/SideChannelMarvels) |

### Secure Boot & TEE Frameworks

| Tool | Description | Notes | Link |
|------|-------------|-------|------|
| **TamaGo** | Bare metal Go framework for ARM/ARM64/RISCV64; includes GoTEE | Powers USB armory, GoKey, armory-boot | [GitHub](https://github.com/usbarmory/tamago) |
| **TF-A (Trusted Firmware-A)** | ARM reference secure world firmware for ARMv8-A | Secure boot + TrustZone reference impl | [GitHub](https://github.com/TrustedFirmware-A/trusted-firmware-a) |
| **OP-TEE** | Open Portable TEE; most studied TEE in research | Run as target for TEE exploit research | [GitHub](https://github.com/OP-TEE/optee_os) |
| **Hafnium** | ARM Secure Partition Manager (SPM) reference implementation | ARMv8.4-A S-EL2 exploitation research | [Trusted Firmware](https://git.trustedfirmware.org/hafnium/hafnium.git) |
| **imx-mkimage / Hab (HABv4)** | NXP i.MX secure boot tooling; understand HABv4 attack surface | Research: HABv4 bypass techniques | [NXP](https://github.com/nxp-imx/imx-mkimage) |
| **wolfBoot** | Minimal portable secure bootloader for bare metal MCUs | Good research/attack target | [GitHub](https://github.com/wolfSSL/wolfBoot) |

---

## 📦 GitHub Repositories

### Awesome Lists & Meta-Collections

| Repository | Stars | Description |
|-----------|-------|-------------|
| [fkie-cad/awesome-embedded-and-iot-security](https://github.com/fkie-cad/awesome-embedded-and-iot-security) | ⭐⭐⭐ | The most comprehensive embedded/IoT security collection; tools, papers, talks, books |
| [hexsecs/awesome-embedded-security](https://github.com/hexsecs/awesome-embedded-security) | ⭐⭐ | Rizin, radare2, Angr, Capstone, ChameleonUltra, Bruce (offensive ESP32 firmware) |
| [IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research](https://github.com/IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research) | ⭐⭐ | ARM exploit dev talks, HITB labs, leaked malware source, SEC661 links |
| [kayranfatih/awesome-iot-and-hardware-security](https://github.com/kayranfatih/awesome-iot-and-hardware-security) | ⭐ | IoT and hardware security tools, frameworks, books aggregation |
| [0xor0ne/awesome-list](https://github.com/0xor0ne/awesome-list) | ⭐⭐ | Curated offensive security blogs, write-ups, and papers - strong embedded section |
| [defcon201/awesome-list-hacking-resources](https://github.com/defcon201/awesome-list-hacking-resources) | ⭐⭐ | 200+ security tool references including EMBA, FACT, Firmwalker |
| [m3y54m/Embedded-Engineering-Roadmap](https://github.com/m3y54m/Embedded-Engineering-Roadmap) | ⭐⭐⭐ | Full roadmap from bare metal programming basics to hardware security research |

### Exploit & Research Codebases

| Repository | Paper/Source | Description |
|-----------|-------------|-------------|
| [RiS3-Lab/p2im](https://github.com/RiS3-Lab/p2im) | USENIX Security '20 | P2IM: QEMU-based peripheral modeling for scalable bare metal firmware testing |
| [ucsb-seclab/hal-fuzz](https://github.com/ucsb-seclab/hal-fuzz) | USENIX Security '20 | HALucinator fuzzing component; HLE for firmware blobs |
| [pr0me/SAFIREFUZZ](https://github.com/pr0me/SAFIREFUZZ) | USENIX Security '23 | Near-native throughput ARM Cortex-M rehosting and fuzzing |
| [fuzzware-fuzzer/fuzzware](https://github.com/fuzzware-fuzzer/fuzzware) | USENIX Security '22 | Self-configuring fuzzer; auto-models MMIO for ARM Cortex-M3/M4 |
| [fuzzware-fuzzer/fuzzware-pipeline](https://github.com/fuzzware-fuzzer/fuzzware-pipeline) | Fuzzware | Pipeline for multi-instance distributed Fuzzware campaigns |
| [fuzzware-fuzzer/fuzzware-emulator](https://github.com/fuzzware-fuzzer/fuzzware-emulator) | Fuzzware | AFL forkserver QEMU emulation backend |
| [icicle-emu/fuzzware](https://github.com/icicle-emu/fuzzware) | Fuzzware | Icicle CPU emulation engine fork for Fuzzware |
| [leveldown-security/SVD-Loader-Ghidra](https://github.com/leveldown-security/SVD-Loader-Ghidra) | stacksmashing | CMSIS-SVD peripheral auto-mapper for Ghidra - essential for bare metal RE |
| [scriptingxss/owasp-fstm](https://github.com/scriptingxss/owasp-fstm) | OWASP | OWASP Firmware Security Testing Methodology - 9-stage process |
| [newaetech/chipwhisperer](https://github.com/newaetech/chipwhisperer) | NewAE | ChipWhisperer power analysis and fault injection platform |
| [newaetech/picoemp](https://github.com/newaetech/picoemp) | NewAE | PicoEMP: RP2040-based low-cost EMFI tool |

### Bare Metal Frameworks

| Repository | Language | Description |
|-----------|---------|-------------|
| [usbarmory/tamago](https://github.com/usbarmory/tamago) | Go | Bare metal Go for ARM, ARM64, AMD64, RISCV64; TEE, secure boot, USB armory |
| [TrustedFirmware-A/trusted-firmware-a](https://github.com/TrustedFirmware-A/trusted-firmware-a) | C | ARM reference TF-A; secure boot chain, TrustZone, SPM |
| [OP-TEE/optee_os](https://github.com/OP-TEE/optee_os) | C | Open Portable TEE - most studied TEE implementation in academia |
| [blackmagic-debug/blackmagic](https://github.com/blackmagic-debug/blackmagic) | C | Black Magic Probe firmware; open source JTAG/SWD debugger |
| [pyocd/pyOCD](https://github.com/pyocd/pyOCD) | Python | Python ARM Cortex-M debugger over SWD/JTAG; scriptable |
| [avatartwo/avatar2](https://github.com/avatartwo/avatar2) | Python | Multi-target orchestration framework for bare metal firmware analysis |
| [wolfSSL/wolfBoot](https://github.com/wolfSSL/wolfBoot) | C | Minimal portable secure bootloader for ARM MCUs |

### Practice & CTF Targets

| Repository | Description |
|-----------|-------------|
| [ghidraninja/arm-bare-metal-1](https://github.com/ghidraninja/arm-bare-metal-1) | ARM bare metal crackme firmware binaries - designed for Ghidra RE practice |
| [cpuu/arm_exploitation](https://github.com/cpuu/arm_exploitation) | ARM binary exploitation practice challenges (used in Matt Brown's series) |
| [IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research](https://github.com/IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research) | Curated list of embedded RE/exploit challenges, HITB lab VMs |
| [posborne/cmsis-svd](https://github.com/posborne/cmsis-svd) | 1,000+ CMSIS-SVD peripheral definition files for RE and tooling |

---

## 🏛 OWASP Projects

| Project | Description | Link |
|---------|-------------|------|
| **OWASP BareMetal** | Builds secure high-assurance bare metal environments: TEEs, TPMs, secure elements, PQC for constrained devices | [owasp.org](https://owasp.org/www-project-baremetal/) |
| **OWASP FSTM** | 9-stage Firmware Security Testing Methodology: acquisition → extraction → static → dynamic → emulation → exploit | [GitBook](https://scriptingxss.gitbook.io/firmware-security-testing-methodology) |
| **OWASP Embedded Application Security** | Secure firmware update pipelines, BOM tracking, legacy binary detection, SBOM generation | [owasp.org](https://owasp.org/www-project-embedded-application-security/) |
| **OWASP IoT Security Testing Guide (ISTG)** | Dedicated firmware test cases, attack surface enumeration, hardware interface testing | [owasp.org](https://owasp.org/owasp-istg/03_test_cases/firmware/) |

---

## 📖 Books

| Title | Author(s) | Year | Focus |
|-------|----------|------|-------|
| **The Hardware Hacking Handbook** | Colin O'Flynn & Jean-Baptiste Bédrune | 2021 | Definitive modern reference: power analysis, fault injection, glitching, RE, JTAG, bare metal exploitation |
| **The Hardware Hacker** | Andrew "bunnie" Huang | 2017 | PCB analysis, chip-off, JTAG fundamentals, hardware RE philosophy |
| **Hacking the Xbox** | Andrew "bunnie" Huang | 2003 | Classic: bare metal Xbox security break - free PDF available online |
| **Practical IoT Hacking** | Fotios Chantzis, Ioannis Stais, et al. | 2021 | UART, JTAG, SWD, firmware extraction, wireless protocols - chapter-by-chapter practicals |
| **The IoT Hacker's Handbook** | Aditya Gupta | 2019 | IoT attack surface, firmware reversing, hardware hacking for IoT pentesting |
| **Building Secure Firmware** | Jiewen Yao & Vincent Zimmer | 2020 | UEFI, TrustZone, TPM, threat modeling, integrity measurement - firmware security architecture |
| **Beyond BIOS: Developing with UEFI** | Vincent Zimmer, Michael Rothman, Suresh Marisetty | 2017 | UEFI internals, platform initialization (PEI/DXE), bare metal boot exploitation research base |
| **Bare-Metal Embedded C Programming** | Packt | 2025 | Modern bare metal C: startup, peripherals, interrupts, RTOS - security-aware development |

---

## 🎓 Courses & Trainings

| Course | Provider | Level | Topics |
|--------|----------|-------|--------|
| **SEC661: ARM Exploit Development** | SANS | Advanced | ARM/THUMB assembly, ROP chains, heap exploitation, bare metal binary exploitation |
| **Hardware Hacking Training** | Black Hat | Advanced | Firmware analysis, JTAG, voltage glitching, SWD unlocking |
| **ChipWhisperer Courses** | NewAE / Colin O'Flynn | Beginner–Advanced | Power analysis, AES SCA, fault injection, free course materials on [learn.chipwhisperer.io](https://learn.chipwhisperer.io) |
| **Embedded Security Training** | Attify | Intermediate | Firmware extraction, Ghidra analysis, IoT device pentesting |
| **Bare Metal Cyber Audio Courses** | Bare Metal Cyber | Beginner–Intermediate | Embedded cybersecurity fundamentals, audio + video format | 
| **Applied Physical Attacks on ARM** | Hardwear.io Training | Advanced | Physical side channel, EMFI, VFI on real ARM targets |
| **OWASP FSTM Self-Study** | OWASP (Free) | All levels | Self-paced: 9-stage firmware security testing methodology |

---

## 🎮 CTF Challenges & Practice

| Resource | Description | Link |
|----------|-------------|------|
| **arm-bare-metal-1** | ARM bare metal crackme binaries by stacksmashing - use with Ghidra + SVD-Loader | [GitHub](https://github.com/ghidraninja/arm-bare-metal-1) |
| **arm_exploitation** | ARM buffer overflow / ROP chain practice challenges | [GitHub](https://github.com/cpuu/arm_exploitation) |
| **DEF CON CTF Archive** | Archive of all DEF CON CTF challenges including embedded/RE categories | [archive.ooo](https://archive.ooo) |
| **Microcorruption** | Online CTF emulating MSP430 bare metal firmware - designed for beginners | [microcorruption.com](https://microcorruption.com) |
| **Flare-On** | Mandiant annual RE CTF with embedded/bare metal challenges | [flare-on.com](https://flare-on.com) |
| **247CTF** | Always-on CTF with RE and binary exploitation challenges | [247ctf.com](https://247ctf.com) |
| **pwn.college** | Free online binary exploitation training with ARM modules | [pwn.college](https://pwn.college) |
| **OpenSecurityTraining2** | Free deep-dive courses: Architecture 1001 (ARM), Malware RE | [ost2.fyi](https://ost2.fyi) |

---

## 🤝 Contributing

Pull requests are welcome! Before submitting:

1. ✅ Resource must be **directly relevant** to bare metal security research or exploitation
2. ✅ Links must be **live and publicly accessible**
3. ✅ Add resources to the **correct section** with a brief, informative description
4. ✅ Prefer primary sources (author blogs, paper PDFs, official repos) over aggregators
5. ✅ Keep descriptions factual and specific - what will the reader *learn or gain*?

**Sections that would benefit from more contributions:**
- RISC-V bare metal security
- Automotive ECU (bare metal) research
- Satellite / space firmware security
- Medical device firmware security

