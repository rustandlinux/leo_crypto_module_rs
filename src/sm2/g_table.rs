//! SM2 基点 G 预计算梳状表 (8 combs × 16 仿射点 = 128 点, 8KB)
//! 自动生成，纯常数时间 8-comb fixed-base 乘法加速

use super::field::FieldElement;
use super::curve::AffinePoint;

pub const G_COMB_TABLE: [[AffinePoint; 16]; 8] = [
    // Comb 0
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05]),
            y: FieldElement([0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe9730aaafd120134, 0xb22b9089c057309c, 0x98e7956584726ce7, 0x0e1431a0d635a584]),
            y: FieldElement([0xbd387023e834ffa6, 0x64198ddf036ab1ae, 0x46e5ebb19124b684, 0xa316fa44233b3c6d]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xdc17ee416ec5df4e, 0x013264bec449a9a2, 0x040a14368468591d, 0x8342ddce1c695dd5]),
            y: FieldElement([0x8cac35d0eaedbd16, 0xa0da8252636e0de4, 0xcf0f5955093a4ef0, 0x6cafbfc96ad9c76a]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xec25045511c09289, 0x83042ba7164079c9, 0x4881640c6e3879a2, 0x77c5babc802452ee]),
            y: FieldElement([0x7a7759a67088f360, 0x02da352cb74be7e9, 0x15800cdbe0338289, 0xad69f7c9501688c6]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xfd27cdba0c8d9f2e, 0x90703c13a7c35396, 0x03164cd474b80e2d, 0x1e08bb9ebc637692]),
            y: FieldElement([0x95bb415b4bc321ac, 0x4abfb785f460eb4c, 0xe7017b28879fb7f0, 0x9c5df02e0a9a9cbf]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x96bbf820986b378d, 0x713cdcc2c799c16c, 0xfacb1dd82ffe2aa7, 0x41cfed62e560e196]),
            y: FieldElement([0x7c0f60c1fb1c8c26, 0x167fb88ba9d1e1a2, 0x4dbd09a7123a3f17, 0xbaa09491ab92d2d4]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x23a8fe0ed0bbcecb, 0x6eefb7e265e3e6e4, 0xbddad5ffda2c5c44, 0x09a43288999e7683]),
            y: FieldElement([0x3f39292d0b800600, 0x2653f60a008756fc, 0x3a5830aa17af8c72, 0xa544c20a78ab3743]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf0c24783f357999b, 0x2c21474c26bfacb3, 0xe3abed6ad3ddb945, 0xbb21b7646031a5ea]),
            y: FieldElement([0x6db3b68b8afc2a09, 0x1aac2f0881306b71, 0x882c3371852eb6f5, 0xadfe0c1ad98e9b6f]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x0e43527ed523a131, 0x4f9f7c0a2aef07c9, 0xac53f37b470901d7, 0xb21c5a29ed11d755]),
            y: FieldElement([0x8102b37a80bd1021, 0x22d1d4810ffebafd, 0xb6f4d386e9131c4e, 0x3aa0e43121926639]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x7c746326cfc4da53, 0xf18682cdc3c60713, 0xc2800e5f916ef105, 0x2622c25f5f580c3e]),
            y: FieldElement([0xb4f391b93e9e58cf, 0x313fcbfa470e489e, 0x54b20128cd354893, 0xc3fb48f5b45e5f39]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x00c38d99d1ba6af0, 0x1124be5e403d35b1, 0x90474f194f3074d4, 0xd5e221460dda188f]),
            y: FieldElement([0x0319be6c32ea3802, 0xd245a3aed0350c5f, 0xc10dbe6e845f228f, 0x2918ed0dcbc4a21d]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x98d62cac4b2ee00d, 0x16927a76582c4ba9, 0x6fa3ff31816b389b, 0x6833bbf1bcba3945]),
            y: FieldElement([0x5cb44a7b3a1b1999, 0xef3c76cb6b71e4a3, 0xdac1093abb028963, 0x09002277a8dd57b9]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf084e98130598025, 0xe966058bf5a37c6e, 0x6f0e0b1d760d30e1, 0x46a5f3d95796539b]),
            y: FieldElement([0xb99f89350b262743, 0xc7e4e705996a6fcb, 0xf0181fa301f8576a, 0x1e3ff4a0bbf6f87a]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x673aabc79eb8151d, 0xacfe21616626d87c, 0xc93acab77d224265, 0x485fee5adb9102cf]),
            y: FieldElement([0xb8c41bf60347a385, 0x725378dc62e2fc3a, 0xd6625258a6037f97, 0xb763b946350a5b34]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x93746ad92b6868ba, 0x29501ba76fa21690, 0x66e49386f6207750, 0x8c39c03bdad553e0]),
            y: FieldElement([0x0bd7d8b31ce3e0be, 0xbb113e3ab9a90fe3, 0x373f955c585749ac, 0x565329fe9618ff8e]),
            infinity: 0,
        },
    ],
    // Comb 1
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0xecb8f92d0cf4efe5, 0x88c47214960e2d22, 0xca9549ef6059f079, 0xd0a3774a7016da7c]),
            y: FieldElement([0xd51c95f61d001cab, 0x2d744defa3feeec1, 0xb7c20cc20afedf2b, 0xbf16c5f171d144a5]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb5b383c6150b0fcd, 0xf948da80ed9b0f4c, 0xcf075225ccd05413, 0x3f31b12c4f62be64]),
            y: FieldElement([0x23b21fc8368c17f6, 0x423d5369400bc690, 0x5335dd1edeac140e, 0xe631c2499493ad61]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xa1c381ab7185dbe5, 0xd41ba8690f2771b8, 0x0db07445a5dbc72f, 0x42bc3b805e322d4b]),
            y: FieldElement([0xfbc477f175b8b223, 0x78ef7a3da4f5aa13, 0x8faec0c591d492da, 0xc4171a5f4e7fd927]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x8487eb9068755cf3, 0x1887394e7fe12541, 0x2e4c65d446af8ca8, 0x72aae645b9e119dc]),
            y: FieldElement([0x958e00941ec6ad73, 0x84a7eec48ce4573e, 0x3d6d00d4f9254b96, 0x4ef44f588e421732]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x4896b318283648c9, 0x18a12f2b30a5e39c, 0x318c09fa6464cf27, 0xdb0f8890cb5f75f6]),
            y: FieldElement([0xe84b1399829f2c53, 0x399e033742ba1832, 0xa37ec6cd172347ff, 0xc3cffdad3adb16ea]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x5c2bb27cb105306b, 0x8147d407bc06fc9a, 0xf53b6fc2f7a8d8ec, 0x396a97beafa7b19b]),
            y: FieldElement([0x4ba89bdcd9c273f9, 0xf689265513358929, 0xcacdb805a8428941, 0xc8e204f5ccf606e9]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xefb3e6a72843e6e6, 0x89d3e4ef67557f0e, 0x40142ee575e23925, 0x6d2c3b4272cac9db]),
            y: FieldElement([0x27fc0ca0355bcd50, 0x7055eb3acb41ea66, 0xf5aa81d28aeef402, 0x654a12725ff19f90]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb720a78f1f8a4a91, 0x59e22211753dbe73, 0x9f5ad99cadd0991a, 0x3a0db8027380726f]),
            y: FieldElement([0x37f0761c7dfb4f1c, 0x68e7098a5ac819cd, 0x9683d61037ffe348, 0x5bf205e52b7b5140]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x068c54357e561d88, 0xab029df6f5320e48, 0xbb1d753907ecf160, 0x1f704b1eacaafa0c]),
            y: FieldElement([0x813e97efc9ace9f5, 0xb6b07a61fcb077f1, 0xe008a7025486fd14, 0x10fa76b28dfa810c]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x2c2212e225f036d7, 0x336b7750abfa2823, 0xace319df4cb9cf67, 0x08b29b1d26bdb2a5]),
            y: FieldElement([0xf5f537dd4b2bf999, 0xae0618e698dac2a0, 0x81e3538fbf6bf6e9, 0xff17f2408dd06827]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x359f641960201008, 0x07221558f5165f7a, 0x32fac7de8f045ef5, 0x10309e14806cdefd]),
            y: FieldElement([0x102feee173861468, 0xe080e7bf9a199170, 0x3fa065cf104dc372, 0x308f40111fa07a96]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x237890bf21ad9090, 0x76a86f810c79b3cb, 0xbc257a81b0a87e61, 0xd1bdbc2b846805f7]),
            y: FieldElement([0x8336b3a07190f944, 0x289c57d24056f760, 0xe8d8df3dec65cbc6, 0x926b74ef3d0fa24a]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x218fb5fcd077b4cc, 0xcc4dfb32191f6591, 0xf21e6f75e6c3a7b5, 0x6823291b306ebe6e]),
            y: FieldElement([0x15a272cc5969bb34, 0xeab90a976d55ee79, 0x7139be2224690ec4, 0xe871d09aa72a7faf]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe177850fc72ac71b, 0x78e3132c322942d1, 0x489a8e78d9d50e47, 0x8b4f49e5190742b0]),
            y: FieldElement([0x699488cdfa750b22, 0x5dcd870897ce7cf5, 0xc2bd8c83a8679ccc, 0x116cc3d63e4c0c3b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x3631dc0d51b8585c, 0x8053a7c6c6e10cd2, 0x0f28bfa0ca0737b4, 0x827b70633247a098]),
            y: FieldElement([0x79e9bf0def76be66, 0x2f5d6444ebc1b82e, 0x64d817b016dfb251, 0xd897a980d336b687]),
            infinity: 0,
        },
    ],
    // Comb 2
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0x4b33e020bad830d2, 0x5c101f9e590dffb3, 0xcd0e0498bc80ecb0, 0x302787f852aa293e]),
            y: FieldElement([0xbfd64ced220f8fc8, 0xcf5cebe0be0ee377, 0xdc03a0388913b128, 0x4b096971fde23279]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf67233c6ba4e4651, 0x8cf956600714d4ac, 0xd70decc371f1f8da, 0xb674732a7078370e]),
            y: FieldElement([0x4270416d4ccc773b, 0xc848ff35de87951e, 0xa61506a8493dfb56, 0xd8371ea9767eb110]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x29bc26072fa1eaea, 0x9e9d8e8b4ca2b22b, 0x79fbbd02c09f7317, 0xa37b7058cad772fe]),
            y: FieldElement([0x4c9070a185ec27a6, 0xc438f0638a0f2dbd, 0xf17e498a7becd7d9, 0x318ac2a9edb8986e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x8348ca15587feffa, 0x585d07407d69e4ad, 0x6fbe5619885a0745, 0x04ee9ebab10b24dd]),
            y: FieldElement([0x5c27075c0f4c12d7, 0xacf4acdc3c51c605, 0x782fa52bfce336d0, 0x6e1d078f483621d2]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xacde2fe5c155ec54, 0x46fda9c70fb30ef4, 0x0a6d0bd9cf6b0f65, 0x02b824ef641c7902]),
            y: FieldElement([0x66e4a8777fdaa0ee, 0x9028d7826921b3d2, 0x0f1203a1c954247f, 0x1c289efb9fe2faae]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf1dbc7e19626b36f, 0x5bfd13f556f13caf, 0xde965a23b7372112, 0x0ed634914529ab85]),
            y: FieldElement([0x917670548a0f53e2, 0x1e69235a0bb62944, 0x977d00b4528191d2, 0xbeaf630e2b8397cb]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x95f0ab05f7368362, 0x32dd0c7028c5972e, 0x75a97ce5b1cd0d69, 0x456bf6e0ded09f22]),
            y: FieldElement([0xb84043c4147202d5, 0x0c16eeb21c6a3c37, 0x28bba0558c90c0d9, 0xcdda4d320d91de5b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xca0ed50cf1edd62f, 0xc3c7ae6fd29f48d9, 0xff47bf288a72ae88, 0x584ddfe5348c6666]),
            y: FieldElement([0x271137e936731fdf, 0x714bc7db88d98bc8, 0xcea912c10da6be30, 0x91cb844dbe62d6a5]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xde91ff25d7ff5fc6, 0xce16c67e013b2659, 0xf5119ce0d71768b5, 0x2160764937ab3be7]),
            y: FieldElement([0xa5a5d8132243d398, 0x5db50ca76352cc51, 0x4dcd38750b663e85, 0x9ba928f09e34a131]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x0c2fd462a7922311, 0x3c729fc2ac3d8f85, 0x4d1c652ebeba8774, 0x10b1968383363423]),
            y: FieldElement([0xe57e5fa9968b0c0d, 0x60dcb741b93bdf41, 0xbd55f621434b9c1a, 0xaf0d12b058b9dd2e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x786cbdc210b112d3, 0x596d0380f3f6dd7d, 0x89dce3aaa162489e, 0x8d14f77dfd527bec]),
            y: FieldElement([0x1e1b2ced058ef0f1, 0x4b13376474ad4529, 0x80084e0df977d678, 0xf0c1d8bde1ccd8a5]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x96d2796373846067, 0x5670dc3f6ab81879, 0xdcdd835531fc4349, 0x8676b3156c99499a]),
            y: FieldElement([0xf987d9ad3d130339, 0x10ca2487a1f1d715, 0x449c52e68c9cfbda, 0x6951f3b88a06d51b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xfcf3fa061fabfa81, 0x22e40d78ed075392, 0xc762d052cf62ff69, 0x53806427c927cea9]),
            y: FieldElement([0x320d0fde6dabdb56, 0x298f71e6e0f624e3, 0x59c4405c1f3d30d3, 0x96f934a4c76f4553]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x59fd6629dae49eab, 0x6ba4b1c510666553, 0xc06c2aec4e65af6f, 0x3373bf1a7145fe80]),
            y: FieldElement([0x3fbd8def32e34bda, 0x0237e05128ad5532, 0x6f38c02643965e06, 0x64e612af782876ff]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x13bec8334358b34d, 0x789aba4427d1672c, 0x52ee4252d93dab96, 0x00e5c8f5bfd926a4]),
            y: FieldElement([0xf95137405299a05b, 0xc4626c2a6a82fd1e, 0x454c920adbecbd59, 0xe65abc1ca296657a]),
            infinity: 0,
        },
    ],
    // Comb 3
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0x4599b8941abd31f0, 0xdb34198d9a1da7d3, 0xa8b89523a0f0217d, 0x2014cc43e56b884e]),
            y: FieldElement([0x6fb94f8849efd4ee, 0xf1b81710287f4ae0, 0x89d38a9a99fd2deb, 0x8179277a72b67a53]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x40372d2d4919affe, 0x2d4a2ea3a009bd16, 0x48f1e7f8c1a62eb1, 0xce083725587a1124]),
            y: FieldElement([0xe874261be7ebadd3, 0x7ca5c156057b93e9, 0xe8b381e5fe39e6ff, 0x2d16b32fd30815c3]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xcd5ea50abc3e2326, 0x02f5b5506f073416, 0x4b15cda006dc1690, 0x83b86c1939fa974d]),
            y: FieldElement([0xc41cb3e0698742ec, 0x7d94e3823c041543, 0xb660c510ba8dd958, 0xe1222301c5caa267]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x9ad2cbd7ab6cf0b4, 0x7a1e67f4f13d1ddf, 0xa58f0c73746003ba, 0x8263e888a64a8fcc]),
            y: FieldElement([0x535cbe37be2452f7, 0x931257666ae81a76, 0x7d2ed0ab3a553701, 0x93d7e7dfb0717d78]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf520b8cdc425677d, 0x85e7730b05908c5e, 0xaea7a11698d721fb, 0x7cc0cb3521e9ae87]),
            y: FieldElement([0x82c084c47a99bd80, 0xbe86e0839ed4f686, 0x7a9e064190111e9b, 0x35e9f076385c4dc4]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x1eeea92d62a28dbf, 0x9bb7d85af342c304, 0x6ab07d985b7324a0, 0xbae6cfd614160b16]),
            y: FieldElement([0x72460da4efb784c5, 0x73cddedef038fce4, 0xb15b03ee3121ee79, 0xe16e857026eea215]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x02f644421a021f1c, 0xc7d6b44f4667d1c6, 0x84b3012988ea0d24, 0x00f13a80a48fe747]),
            y: FieldElement([0xe6a8e4e6de796ba3, 0x91419f8220508125, 0xcead7f5de5b4739e, 0x524faff0062677f3]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x41b6cf7c90f17cba, 0x5d655ff430c7c5f4, 0xc64f29d54ccc7f38, 0xf28e85316124a79e]),
            y: FieldElement([0x1efa8d5167bf1e98, 0x8610027f5d7a33b0, 0x35fe2bb2cb9a40a4, 0xc5cc1bf143d50a0b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x43613b61ac828a16, 0xd5e7ceeffe6e38d2, 0xe12e76c126802b1f, 0xe20b1302399826a2]),
            y: FieldElement([0x0a8c84dade51b1c4, 0x9b9ffb1ec2b4ddbb, 0x68892da4792c3119, 0xacd302c1d7f0c64e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xa76a5e425947d811, 0xe57b17a0b90e902d, 0xc94c16644abe7ded, 0x16779988d90183c9]),
            y: FieldElement([0x3baa9bffc67126b8, 0xb9088fe3e2fc3d93, 0x9d88105e9aa88ed7, 0xdc2c6481a83a80c8]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb8bb2e20e38f294c, 0x10dbd61db887a3be, 0x5608abecf473b153, 0x38a35b0fcb92faf0]),
            y: FieldElement([0x5f41facf7a965afc, 0x644e4178daac49fb, 0x0f07bcc92d6d1f3d, 0xadc7802447d8abc6]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x92d6ecfce086dc6c, 0xbb2de1cf1c6d9036, 0x10aa0cc24b2c9533, 0x5a8818510c87ecad]),
            y: FieldElement([0xbb18bc9e08579298, 0xfd64adaee722df06, 0x589985300a311606, 0x88db217c0e90dd2d]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf3f016cfb854b825, 0xd5fa2505f70cfb08, 0x5cb2233681e0b896, 0x7f35f4b1e0ed9e0c]),
            y: FieldElement([0x63a6efb3251c5c88, 0xd4aefacbaffa6e99, 0xe86f36df913bc697, 0x3108415e47e48715]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x0cf7e9b52fa40e55, 0x24d7c7c978cb55a0, 0x3aaad05ac1b3f6a5, 0xbf6ab793badcc575]),
            y: FieldElement([0xdb9dd36c1533e743, 0xe7ea7d3f4c7f2dcf, 0x59e6069c85858470, 0x73756d46aa2a2005]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x578fb4fc966c626d, 0x2c826ca04d6e3e97, 0x889783b0521a52d7, 0x215142a6db20505f]),
            y: FieldElement([0xfcd2cd74da250756, 0x7860e3cd081cd4e4, 0x428d98df0026ae8a, 0x25f088c9302a2c9c]),
            infinity: 0,
        },
    ],
    // Comb 4
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0x7b9f561a8a914b50, 0x2bf7130e9154d377, 0x6800f696519b4c35, 0xc9e65040568b4c56]),
            y: FieldElement([0x30706e006d98a331, 0x781a12f6e211ce1e, 0x1fff9e3d40562e5f, 0x6356cf468c166747]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe0642d18f9066d73, 0xbe1d2ec3a098b3bf, 0xefee860c21b4954c, 0x4d7c4e6d27b629bb]),
            y: FieldElement([0xcd8f1e038e8b81b0, 0x4a80168e7fe77eb0, 0x4d977591ce247c73, 0x9b30c9f2857e0356]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xd63a7cf7d8010b4b, 0x8a8a41bb3f7c088b, 0x683e2d3d3d3fc231, 0xa3b26e8813035874]),
            y: FieldElement([0xec7693ace69fcd5a, 0x287babff9ee2fa93, 0xca3339dc5f736674, 0x5254fd94b1fcf0fd]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xee0315879c34971b, 0x5829eb07e76545cf, 0xb7a3a6ae33a81bb9, 0xff42daff49c9f710]),
            y: FieldElement([0x894eae85bffb951b, 0x815fe3e2ce70f324, 0x636564cb428b1f12, 0x722e0050a029b0bd]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xebfacf7224e4263d, 0x2f0541a3f53ca04f, 0xde064bf32cef8f7b, 0xdf8efda9c91c9a6b]),
            y: FieldElement([0x428c01cfa56983db, 0xce337b7e4165ac2b, 0x92fa0f4d803ac0ae, 0x4883515f14023713]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x1b824a089f438564, 0x140d6b6813b79efd, 0xfb7234296f3a6936, 0x3350679f637ea91e]),
            y: FieldElement([0x61a6620ef5057c4f, 0x04624f73007856e5, 0x91c96b68dbc9bebf, 0xa0fad541e211018b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x5b07b9900103dd95, 0x9dc16e82fdc4887f, 0x0f152d13380fe2e3, 0x4d67947ac739a2dc]),
            y: FieldElement([0x5201df37c1b64cd4, 0xbab53110fbd20880, 0x276e8743fbe6dea4, 0x20416379e47de12c]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x98bb15ecfe73e699, 0x7533abdc47526489, 0x4b269607491dcc6d, 0x325ec2a077187363]),
            y: FieldElement([0x766faa197e9ab865, 0x1c105b4ac25a9448, 0x0b6b89630531b5ba, 0x32691f112db1a579]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xa51ac65e9fc0aba2, 0xf491ba8de8e14b10, 0xa3bcd0d4adf0b26d, 0xbbc472b71d985b8f]),
            y: FieldElement([0x241bcb719926a449, 0x03614a7dc059b4fd, 0xb9c35f27bd033575, 0x12cac40bb881b7f1]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x3bfe6dfe83dd4e45, 0x02c33cb015a63ec6, 0xc21a6e37f0028ca4, 0x8f56acea4a927dde]),
            y: FieldElement([0x3b85e1180f275940, 0xec350b7ba4b104c7, 0x67ed52ceb66b2529, 0x13aaf83e1b6d28b4]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x97fc6505c141472c, 0x675e0d09e40c84d4, 0xd26e407bbe26801c, 0xceb6c60eac721190]),
            y: FieldElement([0x9572d0596b44a0bb, 0x9e7bca1ec94bc254, 0xeca317786eb182dd, 0xeeffb9e5f717a73e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe1217aefcccd7c71, 0x2aaaef780f2fd360, 0x34e01352eec04eb7, 0xc698db3e89003b24]),
            y: FieldElement([0xcfd67f66632b234d, 0x2f07dfebe9af6433, 0x7166865e6d40c5b1, 0xedee493badb2e70f]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xd4ca8cfb7347efad, 0x9bb019af86f8d023, 0xa9798ba7ab0c3509, 0xd75321725440c0cf]),
            y: FieldElement([0x9cc5584b5fbec9de, 0x89c6290d00155099, 0xb7e998c57cea7e21, 0x1b3e882156edaa91]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x7817bd3dc084dbb0, 0xde4979c80e6ecfad, 0x8a0cac435f4ec99d, 0xc4d16bc32dbf0607]),
            y: FieldElement([0xc88b4b804a42a074, 0xc5ec0d7d338e31b3, 0x8a6a979a79368a4e, 0x4724b39ef61ef02a]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x685adc858727512a, 0xcde88816c2bdf0ab, 0x7ffe859721eeade9, 0x00c229856404ce7b]),
            y: FieldElement([0x32df5ec8f8dd134f, 0x11ecdb6dc2640956, 0xaaa4c85caecacefd, 0x332b5ee43f57e9bb]),
            infinity: 0,
        },
    ],
    // Comb 5
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0x11cf4c2e24424a48, 0x843c73ee37d4471c, 0xb3047fc5617a488b, 0xf2a91709e3cf861c]),
            y: FieldElement([0x844444211c3a60f7, 0x74787a3626679148, 0x115fbd0653d9404b, 0x70fd33656244cef0]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xbc5a62846a436476, 0x6fcc231335dbb9cb, 0xa77d2d9f5012ffbf, 0xcc25e9f44ae4bd14]),
            y: FieldElement([0xd17fcfc41a5e40c6, 0x7d716a5fff085322, 0x9dcbc50bee3077c4, 0xebfe953cdb4a6e61]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x900d78454f76b723, 0x63f0681b96cbb984, 0xc8449b390fcd5042, 0xeb083ac6c912bd8a]),
            y: FieldElement([0xa47c639c62cbedd8, 0xf8144912adaaf822, 0x0eab4751b1e93d14, 0xbadccd9f4f97232c]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xa06d20bc9ff262fb, 0xcba032fdd075868b, 0x70376026943fd973, 0x81c57cbae35c5e02]),
            y: FieldElement([0x1964e700ba871f1b, 0xf03a8c046b265f57, 0xc8ebc9120b950259, 0xd2b0ee30ad32ca8b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb29a337b09f20782, 0x1b6b9fed9279fdd9, 0x4e4d209f0c55db4b, 0xb515d239675f1eac]),
            y: FieldElement([0x857182734328e859, 0x78448eaa049454d6, 0x25f360b0bcaa19dd, 0xd5e6dcce61f4215d]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x18544c6685202def, 0xc819f0c0e2990289, 0x91e4125e1aa149cb, 0x9823ae51cf08490d]),
            y: FieldElement([0xc1e98e62545087ad, 0xc475bdd74982c536, 0xf8808cf4c79e539f, 0x92424fd17931d1ad]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x8fee6f778a642ba9, 0x0a59e34984e8c70c, 0x38ef2892bf006182, 0xb191ba07a628934a]),
            y: FieldElement([0xea002062b32ff1af, 0xdd6634bc925e9808, 0xe19adf9bbf6b8900, 0xfd93b5bd6119fab2]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x8d9daa41b6223f04, 0x803c9c0e841c3fab, 0x60eee3f9c50b42cf, 0xaf4a7a5a77298193]),
            y: FieldElement([0xd379c2e1bf809ad6, 0x903ab4b1f67c0ff2, 0xc779d7ed90f8e637, 0x968b0cc02cf3d363]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x37fff9a6d6b4be42, 0x2897900528e71726, 0x4677871953646694, 0x97156a21fc78a8e8]),
            y: FieldElement([0xeaf9d38ae04ec172, 0x5aba75dbd0552eda, 0x6ab48c5aa05812cc, 0x5822c7ca059c38f9]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x35c942ea1ac625c9, 0x02b9c3a469023755, 0x8bf975bcbc3e9e0a, 0x3ec12bce359a23d8]),
            y: FieldElement([0x7a823316ae87b6c9, 0x0d4e1747b4785eea, 0x920c70c7a52d2d01, 0x271d4ecf1ad99ec5]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb3c72603e00a449a, 0x5612253e410fb23c, 0xe335321948338031, 0xd5a7f8f2fbca52a6]),
            y: FieldElement([0x8bb9651819d80c07, 0x0442baa2bb415fb0, 0xbb6a0e1c0e2bc558, 0x83a66986891ac4db]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf4f3a2448a0559f7, 0x79efd48ece5e1de5, 0xea63ca3a66a00266, 0x71e545e35479cb80]),
            y: FieldElement([0x177c8dc50eed9f86, 0xe2ef0346ca7b3bfb, 0x7fc415861ffc330f, 0xddab282087dc4788]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe9ee1f64d317fc81, 0xd876d2a388a9b81d, 0xa4833650f3ab1969, 0x5478c727882895cd]),
            y: FieldElement([0x86a7f4398218d233, 0xf2559995fc24eccc, 0x789d1d02ab1b5bb9, 0x24f889acf8e43581]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xd20ac2d1c8c66fb5, 0xd0e146097310e246, 0x655d317aa871d9fa, 0xd2046a417a43f5b3]),
            y: FieldElement([0x062a740506618308, 0x8dbbc251ad8f4bf6, 0x38c18b0aa351212f, 0xa7365b52989aed83]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xd3b4c4bcde80dfa3, 0xfa0e5f56f37b2865, 0xe1b1eff181476c38, 0xe4c05306d7916a68]),
            y: FieldElement([0x5b1be2235b6f449a, 0x393f014f992d7d9c, 0xa2c80c223f9f2683, 0x23a38b4f150ea15f]),
            infinity: 0,
        },
    ],
    // Comb 6
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0xfb3992a4202bde39, 0x2549f5643d6bab98, 0x0b56464287712512, 0xd52442b47fde7e50]),
            y: FieldElement([0xa6cefd08a3d3e16e, 0x5b194f0ac83b29bd, 0x6db0edd8906dec8c, 0x7a09095902570c1e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x3b3892d346410cb1, 0x72097f2203a5a136, 0xdb3a1b8098de068d, 0xfb7438e44b1a3890]),
            y: FieldElement([0x8a10d5ea3839d3d9, 0xd9ad034df4bd8126, 0x07d108efd4800261, 0x978d98ba9c5d6c52]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x88ed11449e44d8fd, 0x116af70a242e85b9, 0x7bae3469d132bdfc, 0x1caa4ece2fad9d12]),
            y: FieldElement([0x712bb4926ef69007, 0x9f2cbcb1a294ea1e, 0xdd0892c986d6830b, 0x9d55d91a78e4c440]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x22de997917a86e18, 0xe2ac2321be029111, 0xbfd3439735cc5a17, 0x7a93461f525e13cf]),
            y: FieldElement([0xd433542c5122d6f1, 0x41d2d9de833982c7, 0xe9f1f29a8ec24d27, 0x4ae251f3f3b99d58]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x8ce88b5f98961eaf, 0xc0524006068bd809, 0xe8a970e196b13715, 0xf93a15cc5bef8230]),
            y: FieldElement([0x72f68223bc06389f, 0x12da250601c8c626, 0x028752895187e869, 0xa4b22c13c7fdd73a]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xce5b87dee70f3c4e, 0x322a8af8f0debb8e, 0xa9056531aeaeccf4, 0x7060a2eb7174a278]),
            y: FieldElement([0x4f09730ff4e76d6f, 0x46d11d2feae7d7bf, 0x6f42ba590922552f, 0x68cf2e9bc70214bf]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x85f0e06f640ace80, 0x2f35464bb7086f9e, 0x6dfa9875340faa5b, 0xcdb7a5efaa267c3d]),
            y: FieldElement([0x602132aec12aa89f, 0x735b50a8775d0caa, 0xf9b23cf696944a60, 0x79f9367cf499b683]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x1ae4ee9a1baea574, 0x0d922f2803ae5168, 0x07df28fdca691124, 0x5aad2f318dd457c4]),
            y: FieldElement([0xe0d4f443137384ca, 0xd93d424a6620ea8c, 0x21d544d35067797a, 0xc8a8cc999d8a15bc]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x0ec5c7cc3a4f369c, 0x1b4a2db9bae0081b, 0x66dbaa6804fa0747, 0x9fb09b5d62026eff]),
            y: FieldElement([0xe9540e77ea99b67f, 0x32aa36e8b94d640c, 0xd7de3d99f6217d90, 0x7c8ba9e96473f64d]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xe9e70f0d76670fe8, 0x6b32ccad07fffbc3, 0x87dfa1356193e1a1, 0xa7ee966da8eab958]),
            y: FieldElement([0x5a5d40e64e9c918c, 0x11c73575adb93a92, 0xe1600cefc12b65e7, 0x69a485929cbc71e8]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x4dd74975c06a18e0, 0x85462808db8261a4, 0xb8d4b3c67f9e1072, 0x58e624223cee157d]),
            y: FieldElement([0x6c101eef5d4f8ade, 0x373d9e5bcbfbce79, 0x08594aaa40abfe4f, 0xf5d3bd66d1a4ae37]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xc7aae15f2f712731, 0x4e7798c368d051df, 0xbd942beb3cfcef8c, 0x83f055df66b68f6a]),
            y: FieldElement([0x9d9ceab1c5539209, 0x2bd08818c6b84506, 0xbab44d61a2c38694, 0x587965f149a9a2ba]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x6e35a28b751919a9, 0xfb17ab4f9f6195b2, 0x2d6e24c549e13acd, 0xb77c6338176549b5]),
            y: FieldElement([0x32914411e92e23a9, 0x82e8874dfadb0eb7, 0xeabce016d8c89e66, 0x48dd95bf39443716]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xa0a0f6b687ce82b2, 0x866775a138327cbd, 0x6deaacc0a1d85d6d, 0xadea1eda6e6280fa]),
            y: FieldElement([0xc15b02f97f382452, 0x49006aa0996fca33, 0xe8064dccc1c5159f, 0xf73c644553e439c3]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xff9d2960cee63682, 0x5e28068b9f1d12b7, 0xe1285938b0abcd00, 0x2ce6cbc822726bfb]),
            y: FieldElement([0x59ffbcc54a06f957, 0xff5a215046550a25, 0x3835845356829e84, 0x1969c7c5ae9bddc1]),
            infinity: 0,
        },
    ],
    // Comb 7
    [
        AffinePoint::DUMMY_INFINITY,
        AffinePoint {
            x: FieldElement([0xe74e265bc25dfad3, 0xd03630b9493f44b6, 0xb3270892bfd6d473, 0x5b2d95431c5ee992]),
            y: FieldElement([0xeeb94537a36f7c5f, 0x9befc01d8ab0b81d, 0x483cdb08188b45e5, 0x44c753b701e4648b]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xf77a79cfc0e2b70a, 0x2569c8bcee8cbae7, 0x392a5dbefadb18fc, 0x59bc96b43ce6a0ff]),
            y: FieldElement([0x287f04f48b551005, 0x7efe3aa5a44b2bd8, 0x0e9cb8ed6ac447d7, 0x9b4eb10a7783bdd0]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x4f0b58eb2f2fcf48, 0xc84fb37f9f922d7b, 0x94e2cdc008c96710, 0x3098bd9078001c7d]),
            y: FieldElement([0x83bfb6bf286fc1b4, 0x2985ec53a57a4de1, 0x623d1d20582a3723, 0x8985fa7ffed45249]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x6f154f09a9e0eeae, 0x2246e6feab05a657, 0x4d7c1c811045b85d, 0xde99ea37d3bb7432]),
            y: FieldElement([0x058f818763184ff4, 0x2a223421d134bfc3, 0x1560dbed23120320, 0x37243c9576a3de9c]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xfcb90a81ee79465e, 0x83c8aaf8613b4234, 0xd3e0802d8890d3f5, 0xa525ffbe87a2d0a5]),
            y: FieldElement([0x409c0a399a7ca008, 0xd2cba741912c5cc2, 0x3b9d7fd48869b0cd, 0x2ce3376dbd430291]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x570e4951c7b59ea7, 0x55407e529968e841, 0x64f0c3e43416fb75, 0x7dbbc2bdb001a7cd]),
            y: FieldElement([0x5141437c86d0d556, 0x5f6c4d8feea31a0a, 0x570fcee63c26fe12, 0xfc1f739df69b10d1]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x2fc4a732029670e7, 0x1f261e8cff7d5536, 0xe82aed29b2882a34, 0x448e5dd2e9a10e34]),
            y: FieldElement([0xaf0e9ddc8f7f6d0f, 0x3fb5bce1193761cc, 0x0487a89ec911a8e1, 0x2eb60467e28f8fec]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x79447ef9dfa782a4, 0x6dadc8e174cd9500, 0x0574020edc38f762, 0x17596d7ee2ee7a14]),
            y: FieldElement([0x9ef75af79e1f8adc, 0x5ac5f216a4791da0, 0x1583226b7b7b5d80, 0x59f3f053a21c26cc]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xc1c182e3ef2bfd9b, 0x2158d9a436deb967, 0xe52602cf842a825c, 0xc357a0c517716c39]),
            y: FieldElement([0x4e1ce500d608c2c9, 0x5fc61c17112e0631, 0x6466e9fd8aa1e635, 0xdb5982548c353581]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xcdeaba89546b1aec, 0x003ed08d72de079f, 0x1ff00c899f8fdcf3, 0x7ed711ac355d50fe]),
            y: FieldElement([0x634546096a5265d8, 0x4235f24a4ea14247, 0xace3613f75b61187, 0x25097fdac1fc264f]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xc8612105915ed147, 0x3151da60fd236e25, 0xd511057b94ca86ce, 0x78ca343e0bdb4ac9]),
            y: FieldElement([0x1baaae6d64e6645f, 0x0525af117eb81ecb, 0xa6c22397b4e77ec7, 0xc21d8423a91b375e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x92dc2def5e7e1754, 0x525d1f47859c8ccd, 0x6edf8e1f3c23a3e3, 0x2122ffdfbc16403f]),
            y: FieldElement([0xaf2fd3a4dd1e35ec, 0x93464ce574af5dca, 0x455024cd9a35ac9e, 0x5cb050274f60a715]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x6f8198be74dd617f, 0xf723980c00352046, 0xd425640a2068d36e, 0x8bb80eacdd748ec8]),
            y: FieldElement([0x29c067facb271c69, 0x9742367cd49b40fb, 0xcbdb345cdf70256d, 0x0b1fe910f4ab0224]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0xb00e7a4e9845f3c5, 0x1a0355e6cc8cf2b5, 0xd3de146ce782c502, 0xcbfeef83cc90d824]),
            y: FieldElement([0x622044d2977f7b64, 0xe71887d7653784d7, 0xbfdadbc06c696e0a, 0x9a8a4a7c2e8e9a1e]),
            infinity: 0,
        },
        AffinePoint {
            x: FieldElement([0x3dc1a48907aadee2, 0x55c483ad7d206514, 0x3b9d736b2c9a210a, 0x8553d752db496ca3]),
            y: FieldElement([0xc580742bf06fa5bb, 0x2bc33829a16a9190, 0x0cad7884db8d8702, 0xe74f3608f8efe245]),
            infinity: 0,
        },
    ],
];

/// 基点 G 的 8 个奇数倍数预计算表 (1G, 3G, 5G, 7G, 9G, 11G, 13G, 15G)
/// 仿射坐标 (Montgomery 域表达)，用于 Straus-Shamir 联合点乘与混合加法
pub const G_ODD_TABLE: [AffinePoint; 8] = [
    // [1]G
    AffinePoint {
        x: FieldElement([0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05]),
        y: FieldElement([0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd]),
        infinity: 0,
    },
    // [3]G
    AffinePoint {
        x: FieldElement([0x1cda54fdab589e4a, 0x26765289db4f0a0d, 0x0a265a308ceb4a0a, 0x3019fd6bfe887c64]),
        y: FieldElement([0x0a10fbe94b2fc190, 0xf40aa52b87cbce60, 0xcc496bfa6dc13c97, 0x28ad34785bb3fbb4]),
        infinity: 0,
    },
    // [5]G
    AffinePoint {
        x: FieldElement([0x9a5756336a9c8162, 0x15aa58f221dfcc53, 0x7ad354bf1ef5f4c5, 0x0f443ef363f875b9]),
        y: FieldElement([0x2e81d68fd3450133, 0xb30f4bbde3607d18, 0xb1826a4c362258ef, 0x7b415276142a6768]),
        infinity: 0,
    },
    // [7]G
    AffinePoint {
        x: FieldElement([0xaa3531c781f06784, 0x0b89419307132520, 0x84ee5b69acfe18c5, 0xbbf492e0d9fbec28]),
        y: FieldElement([0x313a35c1e5f6186d, 0x0e449a2e757a01b8, 0x96c9b9922bd99baf, 0x2ba05a8f3b84d777]),
        infinity: 0,
    },
    // [9]G
    AffinePoint {
        x: FieldElement([0x98e795c330fbde86, 0x8e5e0495ab21af8f, 0x3925bf83b48669b4, 0x77d88740469522c8]),
        y: FieldElement([0x8fbf8b5b987b04ce, 0x63c563a83aff4428, 0x5dc1116553a6e969, 0x822a6c2432697f4c]),
        infinity: 0,
    },
    // [11]G
    AffinePoint {
        x: FieldElement([0x2b252ad03421e115, 0x7557c8c7c6affc01, 0xd90c19fd8a509267, 0x483da168e0d871c8]),
        y: FieldElement([0x72d6f9b3c10729bf, 0x5dd8402115b7061e, 0x9bfea2db9f2c587d, 0x528398a798641ec2]),
        infinity: 0,
    },
    // [13]G
    AffinePoint {
        x: FieldElement([0x34e51c6a8000fe4e, 0x7da2bdfd89c46941, 0x667ba91de1bc2b2e, 0x3c80c9d010a73e5c]),
        y: FieldElement([0x4fadebbec7f5c64d, 0xaef09eb43ea35052, 0x167ee11b26ec55f9, 0x45fa508a85189260]),
        infinity: 0,
    },
    // [15]G
    AffinePoint {
        x: FieldElement([0xf3489343dde97d4d, 0x9c14e38abbb2ce1f, 0x25866911cfddf221, 0x0df89411460efef1]),
        y: FieldElement([0xf713f30e73ae8326, 0xd9be66a8cdd274a1, 0xdf915ae236885947, 0x2c5c1e9e7878b781]),
        infinity: 0,
    },
];
