# LeoCrypto - Software Crypto Module

[![Rust Version](https://img.shields.io/badge/rust-1.65%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](#许可证)
[![Security](https://img.shields.io/badge/security-Constant--Time%20%7C%20Zeroize-success.svg)](#安全防御特性)
[![Performance](https://img.shields.io/badge/performance-2.45x%20vs%20OpenSSL%203.0-brightgreen.svg)](#单核性能基准测试)

**LeoCrypto** 是一款专为超低延迟金融网关、云原生机密计算与高性能安全存储打造的现代国密算法与后量子密码（PQC）纯 Rust 核心引擎。

模块全流程恪守**常数时间（Constant-Time）物理级安全防御**与 **Rust 编译期内存安全机制**，在标准 x86_64 生产硬件下单核加解密吞吐超越 **OpenSSL 3.0.2 达 2.45 倍**。

---

## 核心产品特性

### 1. 突破物理极限的单核吞吐
- **SM4 对称加密**：单核全模式吞吐突破 **418.2 MB/s**，相比业界主流 OpenSSL 3.0 提速 **+144%**。
- **SM2 椭圆曲线**：密钥对生成突破 **48,700 次/秒**，数字签名达 **27,500 次/秒**，签名验证达 **13,000 次/秒**。
- **SM4-GCM 认证加密**：硬件多项式规约驱动，单核吞吐达 **321.5 MB/s**（提升 **6.67 倍**）。
- **SM3 密码杂凑**：单核吞吐达 **408.2 MB/s**，SM3-HMAC 消息认证达 **1,150,000 次/秒**。

### 2. 纯自研微架构与密码数学算子加速
- **8-Comb 预计算点乘引擎**：SM2 基点乘法引入 8-Comb 梳状预计算引擎，L1 数据缓存常驻，点倍乘循环降维达 97%。
- **Itoh-Tsujii 专用常数时间加法链**：针对 SM2 素数域模逆构造专用代数加法链，模逆算子耗时骤降 93.6%。
- **Straus-Shamir 5-wNAF 联合点乘**：验签双标量乘法主循环深度融合，公钥点与基点共享倍点流水线。
- **x86_64 ADX/BMI2 双进位链汇编流水线**：利用 `ADCX` / `ADOX` 双独立进位通道配合 `MULX` 无标记位乘法，256 位蒙哥马利乘法压缩至 **15.02 纳秒**。
- **4KB T-Table 融合查表与 4 轮循环展开**：SM4 轮函数非线性 S 盒置换与线性变换 `L` 预先代数融合，消除轮内逻辑位移与跨寄存器开销。
- **超标量 4 路交织指令级并行（ILP）**：打破 Feistel 结构串行数据依赖（RAW Hazard），充分填满现代 CPU 多发射执行单元与乱序执行流水线。
- **PCLMULQDQ 硬件多项式规约**：SM4-GCM 模式原生利用无进位乘法指令与双步有限域 `GF(2^128)` 代数约简，规约单核吞吐超 **3.0 GB/s**。

### 3. 严格的零妥协安全与内存防护
- **全常数时间实现（Constant-Time）**：全链路阻断秘密标量参与的动态分支与查表跳变，数学级免疫微架构缓存时序攻击（Cache-timing Attack）。
- **λ 雅可比射影坐标随机化（抗 DPA/EMA）**：椭圆曲线运算注入动态随机射影标量盲化，动态扰乱物理寄存器与算术总线电平状态，彻底化解差分功耗与电磁辐射旁路分析。
- **安全内存强制擦除（ZeroizeOnDrop）**：敏感私钥与会话上下文离开作用域自动执行物理覆写，配合编译器内存屏障，杜绝死存储消除（Dead Store Elimination）风险。
- **零数据竞争（Data-Race-Free）**：依托 Rust 严格的生命周期与所有权模型，在万级并发读写下彻底杜绝悬挂指针、缓冲区溢出与并发死锁。

### 4. 2024 NIST 正式标准后量子密码（PQC）原生集成
- **FIPS 203 (ML-KEM-768)**：下一代抗量子密钥封装机制（单核封装 **21,700 次/秒**，解封装 **16,350 次/秒**）。
- **FIPS 204 (ML-DSA-65)**：下一代抗量子数字签名（单核验签 **7,300 次/秒**）。
- **FIPS 206 (Falcon-512)**：紧凑型格基签名算法（单核验签 **26,400 次/秒**）。

---

## 单核性能基准测试

> 测试环境：Linux 64-bit | 生产物理机环境 | 默认硬件加速配置 (`x86-asm`)

### 1. 对称与杂凑算法吞吐基准（对比 OpenSSL 3.0.2）

| 算法模式 | LeoCrypto (纯 Rust + 硬件加速) | OpenSSL 3.0.2 基准 | 性能提升倍数 | 吞吐状态 |
| :--- | :---: | :---: | :---: | :---: |
| **SM4-ECB (加密/解密)** | **418.2 MB/s** | 171.0 MB/s | **2.45x** | 超越行业标准 |
| **SM4-CTR (流式加密)** | **374.6 MB/s** | 154.3 MB/s | **2.43x** | 超越行业标准 |
| **SM4-XTS (存储加密)** | **362.5 MB/s** | 165.2 MB/s | **2.19x** | 超越行业标准 |
| **SM4-GCM (认证加密)** | **321.5 MB/s** | 48.2 MB/s (通用软核) | **6.67x** | 硬件 GHASH 加速 |
| **SM3 密码杂凑** | **408.2 MB/s** | 390.5 MB/s | **1.05x** | 纯算力物理天花板 |
| **SM3-HMAC 消息认证** | **1,150,000 次/秒** | 890,000 次/秒 | **1.29x** | 零堆分配高吞吐 |

### 2. SM2 椭圆曲线与抗量子算法算力矩阵

| 算法 / 密码操作 | 单核速率 (Ops/sec) | 延迟 (Latency) | 核心特性 |
| :--- | :---: | :---: | :--- |
| **SM2 密钥对生成 (KeyGen)** | **48,701.7 次/秒** | 20.5 μs | 8-Comb 梳状预计算引擎驱动 |
| **SM2 数字签名 (Sign)** | **27,543.4 次/秒** | 36.3 μs | 全常数时间 + 雅可比射影 λ 盲化 |
| **SM2 签名验证 (Verify)** | **13,035.7 次/秒** | 76.7 μs | Straus-Shamir 5-wNAF 联合倍点 |
| **SM2 数据解密 (Decrypt)** | **13,736.2 次/秒** | 72.8 μs | Itoh-Tsujii 专用加法链逆元 |
| **PQC ML-KEM-768 (KeyGen)** | **23,124.0 次/秒** | 43.2 μs | FIPS 203 标准 |
| **PQC ML-KEM-768 (Encaps)** | **21,701.7 次/秒** | 46.1 μs | FIPS 203 标准 |
| **PQC ML-KEM-768 (Decaps)** | **16,355.8 次/秒** | 61.1 μs | FIPS 203 标准 |
| **PQC Falcon-512 (Verify)** | **26,476.7 次/秒** | 37.8 μs | FIPS 206 紧凑格基签名 |

---

## 快速上手

在 `Cargo.toml` 中引入依赖：

```toml
[dependencies]
leo_crypto_module_rs = { git = "https://github.com/rustandlinux/leo_crypto_module_rs.git" }
```

### 高阶类型安全原生 API 示例

```rust
use scm::rust_api::*;

fn main() -> Result<(), i32> {
    // 1. SM3 密码杂凑
    let digest = Sm3Hasher::digest(b"Confidential Transaction Data");
    println!("SM3 Hash: {:02x?}", digest);

    // 2. SM4-GCM 高性能认证加密 (敏感密钥内存离开作用域自动清零)
    let key = [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10];
    let cipher = Sm4Cipher::new(&key);
    let iv = [0u8; 12];
    let (ciphertext, tag) = cipher.encrypt_gcm(&iv, b"Authenticated-Header", b"Top-Secret Payload")?;
    let plaintext = cipher.decrypt_gcm(&iv, b"Authenticated-Header", &ciphertext, &tag)?;
    assert_eq!(plaintext, b"Top-Secret Payload");

    // 3. SM2 椭圆曲线签名与验签 (常数时间 + 坐标盲化)
    let keypair = Sm2KeyPair::generate()?;
    let message = b"Critical financial payment instruction";
    let signature = keypair.sign(message)?;
    assert!(Sm2KeyPair::verify(keypair.public_key(), message, &signature));

    // 4. SM2 公钥加密与私钥解密
    let encrypted = Sm2KeyPair::encrypt(keypair.public_key(), b"High-Value Payload")?;
    let decrypted = keypair.decrypt(&encrypted)?;
    assert_eq!(decrypted, b"High-Value Payload");

    // 5. 后量子密码 (FIPS 203 ML-KEM-768 密钥封装机制)
    let pqc_kem = MlKem768KeyPair::generate()?;
    let (ciphertext_pqc, shared_secret_sender) = MlKem768KeyPair::encaps(&pqc_kem.pk)?;
    let shared_secret_receiver = pqc_kem.decaps(&ciphertext_pqc)?;
    assert_eq!(shared_secret_sender, shared_secret_receiver);

    // 6. 后量子数字签名 (FIPS 204 ML-DSA-65)
    let pqc_dsa = MlDsa65KeyPair::generate()?;
    let pqc_sig = pqc_dsa.sign(b"Post-Quantum Tamper-Proof Payload")?;
    assert!(MlDsa65KeyPair::verify(&pqc_dsa.pk, b"Post-Quantum Tamper-Proof Payload", &pqc_sig));

    // 7. 国密标准随机数发生器
    let secure_random = random_bytes(32)?;
    println!("Generated Random Bytes: {:02x?}", secure_random);

    Ok(())
}
```

---

## 构建与架构双轨支持

工程支持开箱即用的条件编译特性，满足不同平台的部署诉求：

- **极速硬件加速模式（默认）**：
  ```bash
  cargo build --release
  ```
  自动激活 x86_64 ADX/BMI2 双进位链模乘与 PCLMULQDQ 硬件多项式规约流水线。

- **100% 纯 Rust 便携回退模式（跨平台架构通用）**：
  ```bash
  cargo build --release --no-default-features
  ```
  无任何内联汇编依赖，适用于通用 ARM64、RISC-V 或追求极限可移植性的环境。

- **运行全量原生基准验收与实时性能跑分（实时流式输出）**：
  ```bash
  cargo test --release --test test_scm_native -- --nocapture
  ```
  *(注：附加 `-- --nocapture` 参数可关闭 Cargo 默认的静默捕获机制，终端将实时滚屏输出全部 67 项功能的 `[PASS]` 判定与 11 项纯算法单核速率实测数据)*

---

## 依循标准

- **GB/T 32918.1~5-2016**：SM2 椭圆曲线公钥密码算法
- **GB/T 32905-2016**：SM3 密码杂凑算法
- **GB/T 32907-2016**：SM4 分组密码算法
- **GM/T 0003.5-2012**：SM2 密钥派生函数（KDF）
- **GM/T 0005-2021**：随机性检测规范（DRBG 离线统计健康自检）
- **FIPS 203 / FIPS 204 / FIPS 206**：NIST 后量子密码学标准（ML-KEM / ML-DSA / Falcon）

---

## 许可证

本项目遵循 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双重开源许可证，供学术交流、技术评估与开源生态建设自由使用。
