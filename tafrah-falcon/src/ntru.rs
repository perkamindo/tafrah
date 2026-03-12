extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::fft::{
    fft, ifft, poly_add, poly_adj_fft, poly_invnorm2_fft, poly_mul_autoadj_fft, poly_mul_fft,
    poly_muladj_fft, poly_sub,
};
use crate::fpr::{fpr_lt, fpr_mul, fpr_rint, fpr_sqr, Fpr, GmTable};
use crate::modp::{
    modp_add, modp_intt2_ext, modp_mkgm2, modp_montymul, modp_ninv31, modp_norm, modp_ntt2_ext,
    modp_poly_rec_res, modp_r2, modp_rx, modp_set, modp_sub, SmallPrime,
};
use crate::reduction::{
    poly_big_to_fp, poly_sub_scaled, poly_sub_scaled_ntt, BITLENGTH, DEPTH_INT_FG, MAX_BL_LARGE,
};
use crate::zint::{
    zint_bezout, zint_mod_small_signed, zint_mul_small, zint_one_to_plain, zint_rebuild_crt,
};

pub(crate) const MAX_BL_SMALL: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];

pub(crate) const SMALL_PRIMES: [SmallPrime; 308] = [
    SmallPrime {
        p: 2147473409,
        g: 383167813,
        s: 10239,
    },
    SmallPrime {
        p: 2147389441,
        g: 211808905,
        s: 471403745,
    },
    SmallPrime {
        p: 2147387393,
        g: 37672282,
        s: 1329335065,
    },
    SmallPrime {
        p: 2147377153,
        g: 1977035326,
        s: 968223422,
    },
    SmallPrime {
        p: 2147358721,
        g: 1067163706,
        s: 132460015,
    },
    SmallPrime {
        p: 2147352577,
        g: 1606082042,
        s: 598693809,
    },
    SmallPrime {
        p: 2147346433,
        g: 2033915641,
        s: 1056257184,
    },
    SmallPrime {
        p: 2147338241,
        g: 1653770625,
        s: 421286710,
    },
    SmallPrime {
        p: 2147309569,
        g: 631200819,
        s: 1111201074,
    },
    SmallPrime {
        p: 2147297281,
        g: 2038364663,
        s: 1042003613,
    },
    SmallPrime {
        p: 2147295233,
        g: 1962540515,
        s: 19440033,
    },
    SmallPrime {
        p: 2147239937,
        g: 2100082663,
        s: 353296760,
    },
    SmallPrime {
        p: 2147235841,
        g: 1991153006,
        s: 1703918027,
    },
    SmallPrime {
        p: 2147217409,
        g: 516405114,
        s: 1258919613,
    },
    SmallPrime {
        p: 2147205121,
        g: 409347988,
        s: 1089726929,
    },
    SmallPrime {
        p: 2147196929,
        g: 927788991,
        s: 1946238668,
    },
    SmallPrime {
        p: 2147178497,
        g: 1136922411,
        s: 1347028164,
    },
    SmallPrime {
        p: 2147100673,
        g: 868626236,
        s: 701164723,
    },
    SmallPrime {
        p: 2147082241,
        g: 1897279176,
        s: 617820870,
    },
    SmallPrime {
        p: 2147074049,
        g: 1888819123,
        s: 158382189,
    },
    SmallPrime {
        p: 2147051521,
        g: 25006327,
        s: 522758543,
    },
    SmallPrime {
        p: 2147043329,
        g: 327546255,
        s: 37227845,
    },
    SmallPrime {
        p: 2147039233,
        g: 766324424,
        s: 1133356428,
    },
    SmallPrime {
        p: 2146988033,
        g: 1862817362,
        s: 73861329,
    },
    SmallPrime {
        p: 2146963457,
        g: 404622040,
        s: 653019435,
    },
    SmallPrime {
        p: 2146959361,
        g: 1936581214,
        s: 995143093,
    },
    SmallPrime {
        p: 2146938881,
        g: 1559770096,
        s: 634921513,
    },
    SmallPrime {
        p: 2146908161,
        g: 422623708,
        s: 1985060172,
    },
    SmallPrime {
        p: 2146885633,
        g: 1751189170,
        s: 298238186,
    },
    SmallPrime {
        p: 2146871297,
        g: 578919515,
        s: 291810829,
    },
    SmallPrime {
        p: 2146846721,
        g: 1114060353,
        s: 915902322,
    },
    SmallPrime {
        p: 2146834433,
        g: 2069565474,
        s: 47859524,
    },
    SmallPrime {
        p: 2146818049,
        g: 1552824584,
        s: 646281055,
    },
    SmallPrime {
        p: 2146775041,
        g: 1906267847,
        s: 1597832891,
    },
    SmallPrime {
        p: 2146756609,
        g: 1847414714,
        s: 1228090888,
    },
    SmallPrime {
        p: 2146744321,
        g: 1818792070,
        s: 1176377637,
    },
    SmallPrime {
        p: 2146738177,
        g: 1118066398,
        s: 1054971214,
    },
    SmallPrime {
        p: 2146736129,
        g: 52057278,
        s: 933422153,
    },
    SmallPrime {
        p: 2146713601,
        g: 592259376,
        s: 1406621510,
    },
    SmallPrime {
        p: 2146695169,
        g: 263161877,
        s: 1514178701,
    },
    SmallPrime {
        p: 2146656257,
        g: 685363115,
        s: 384505091,
    },
    SmallPrime {
        p: 2146650113,
        g: 927727032,
        s: 537575289,
    },
    SmallPrime {
        p: 2146646017,
        g: 52575506,
        s: 1799464037,
    },
    SmallPrime {
        p: 2146643969,
        g: 1276803876,
        s: 1348954416,
    },
    SmallPrime {
        p: 2146603009,
        g: 814028633,
        s: 1521547704,
    },
    SmallPrime {
        p: 2146572289,
        g: 1846678872,
        s: 1310832121,
    },
    SmallPrime {
        p: 2146547713,
        g: 919368090,
        s: 1019041349,
    },
    SmallPrime {
        p: 2146508801,
        g: 671847612,
        s: 38582496,
    },
    SmallPrime {
        p: 2146492417,
        g: 283911680,
        s: 532424562,
    },
    SmallPrime {
        p: 2146490369,
        g: 1780044827,
        s: 896447978,
    },
    SmallPrime {
        p: 2146459649,
        g: 327980850,
        s: 1327906900,
    },
    SmallPrime {
        p: 2146447361,
        g: 1310561493,
        s: 958645253,
    },
    SmallPrime {
        p: 2146441217,
        g: 412148926,
        s: 287271128,
    },
    SmallPrime {
        p: 2146437121,
        g: 293186449,
        s: 2009822534,
    },
    SmallPrime {
        p: 2146430977,
        g: 179034356,
        s: 1359155584,
    },
    SmallPrime {
        p: 2146418689,
        g: 1517345488,
        s: 1790248672,
    },
    SmallPrime {
        p: 2146406401,
        g: 1615820390,
        s: 1584833571,
    },
    SmallPrime {
        p: 2146404353,
        g: 826651445,
        s: 607120498,
    },
    SmallPrime {
        p: 2146379777,
        g: 3816988,
        s: 1897049071,
    },
    SmallPrime {
        p: 2146363393,
        g: 1221409784,
        s: 1986921567,
    },
    SmallPrime {
        p: 2146355201,
        g: 1388081168,
        s: 849968120,
    },
    SmallPrime {
        p: 2146336769,
        g: 1803473237,
        s: 1655544036,
    },
    SmallPrime {
        p: 2146312193,
        g: 1023484977,
        s: 273671831,
    },
    SmallPrime {
        p: 2146293761,
        g: 1074591448,
        s: 467406983,
    },
    SmallPrime {
        p: 2146283521,
        g: 831604668,
        s: 1523950494,
    },
    SmallPrime {
        p: 2146203649,
        g: 712865423,
        s: 1170834574,
    },
    SmallPrime {
        p: 2146154497,
        g: 1764991362,
        s: 1064856763,
    },
    SmallPrime {
        p: 2146142209,
        g: 627386213,
        s: 1406840151,
    },
    SmallPrime {
        p: 2146127873,
        g: 1638674429,
        s: 2088393537,
    },
    SmallPrime {
        p: 2146099201,
        g: 1516001018,
        s: 690673370,
    },
    SmallPrime {
        p: 2146093057,
        g: 1294931393,
        s: 315136610,
    },
    SmallPrime {
        p: 2146091009,
        g: 1942399533,
        s: 973539425,
    },
    SmallPrime {
        p: 2146078721,
        g: 1843461814,
        s: 2132275436,
    },
    SmallPrime {
        p: 2146060289,
        g: 1098740778,
        s: 360423481,
    },
    SmallPrime {
        p: 2146048001,
        g: 1617213232,
        s: 1951981294,
    },
    SmallPrime {
        p: 2146041857,
        g: 1805783169,
        s: 2075683489,
    },
    SmallPrime {
        p: 2146019329,
        g: 272027909,
        s: 1753219918,
    },
    SmallPrime {
        p: 2145986561,
        g: 1206530344,
        s: 2034028118,
    },
    SmallPrime {
        p: 2145976321,
        g: 1243769360,
        s: 1173377644,
    },
    SmallPrime {
        p: 2145964033,
        g: 887200839,
        s: 1281344586,
    },
    SmallPrime {
        p: 2145906689,
        g: 1651026455,
        s: 906178216,
    },
    SmallPrime {
        p: 2145875969,
        g: 1673238256,
        s: 1043521212,
    },
    SmallPrime {
        p: 2145871873,
        g: 1226591210,
        s: 1399796492,
    },
    SmallPrime {
        p: 2145841153,
        g: 1465353397,
        s: 1324527802,
    },
    SmallPrime {
        p: 2145832961,
        g: 1150638905,
        s: 554084759,
    },
    SmallPrime {
        p: 2145816577,
        g: 221601706,
        s: 427340863,
    },
    SmallPrime {
        p: 2145785857,
        g: 608896761,
        s: 316590738,
    },
    SmallPrime {
        p: 2145755137,
        g: 1712054942,
        s: 1684294304,
    },
    SmallPrime {
        p: 2145742849,
        g: 1302302867,
        s: 724873116,
    },
    SmallPrime {
        p: 2145728513,
        g: 516717693,
        s: 431671476,
    },
    SmallPrime {
        p: 2145699841,
        g: 524575579,
        s: 1619722537,
    },
    SmallPrime {
        p: 2145691649,
        g: 1925625239,
        s: 982974435,
    },
    SmallPrime {
        p: 2145687553,
        g: 463795662,
        s: 1293154300,
    },
    SmallPrime {
        p: 2145673217,
        g: 771716636,
        s: 881778029,
    },
    SmallPrime {
        p: 2145630209,
        g: 1509556977,
        s: 837364988,
    },
    SmallPrime {
        p: 2145595393,
        g: 229091856,
        s: 851648427,
    },
    SmallPrime {
        p: 2145587201,
        g: 1796903241,
        s: 635342424,
    },
    SmallPrime {
        p: 2145525761,
        g: 715310882,
        s: 1677228081,
    },
    SmallPrime {
        p: 2145495041,
        g: 1040930522,
        s: 200685896,
    },
    SmallPrime {
        p: 2145466369,
        g: 949804237,
        s: 1809146322,
    },
    SmallPrime {
        p: 2145445889,
        g: 1673903706,
        s: 95316881,
    },
    SmallPrime {
        p: 2145390593,
        g: 806941852,
        s: 1428671135,
    },
    SmallPrime {
        p: 2145372161,
        g: 1402525292,
        s: 159350694,
    },
    SmallPrime {
        p: 2145361921,
        g: 2124760298,
        s: 1589134749,
    },
    SmallPrime {
        p: 2145359873,
        g: 1217503067,
        s: 1561543010,
    },
    SmallPrime {
        p: 2145355777,
        g: 338341402,
        s: 83865711,
    },
    SmallPrime {
        p: 2145343489,
        g: 1381532164,
        s: 641430002,
    },
    SmallPrime {
        p: 2145325057,
        g: 1883895478,
        s: 1528469895,
    },
    SmallPrime {
        p: 2145318913,
        g: 1335370424,
        s: 65809740,
    },
    SmallPrime {
        p: 2145312769,
        g: 2000008042,
        s: 1919775760,
    },
    SmallPrime {
        p: 2145300481,
        g: 961450962,
        s: 1229540578,
    },
    SmallPrime {
        p: 2145282049,
        g: 910466767,
        s: 1964062701,
    },
    SmallPrime {
        p: 2145232897,
        g: 816527501,
        s: 450152063,
    },
    SmallPrime {
        p: 2145218561,
        g: 1435128058,
        s: 1794509700,
    },
    SmallPrime {
        p: 2145187841,
        g: 33505311,
        s: 1272467582,
    },
    SmallPrime {
        p: 2145181697,
        g: 269767433,
        s: 1380363849,
    },
    SmallPrime {
        p: 2145175553,
        g: 56386299,
        s: 1316870546,
    },
    SmallPrime {
        p: 2145079297,
        g: 2106880293,
        s: 1391797340,
    },
    SmallPrime {
        p: 2145021953,
        g: 1347906152,
        s: 720510798,
    },
    SmallPrime {
        p: 2145015809,
        g: 206769262,
        s: 1651459955,
    },
    SmallPrime {
        p: 2145003521,
        g: 1885513236,
        s: 1393381284,
    },
    SmallPrime {
        p: 2144960513,
        g: 1810381315,
        s: 31937275,
    },
    SmallPrime {
        p: 2144944129,
        g: 1306487838,
        s: 2019419520,
    },
    SmallPrime {
        p: 2144935937,
        g: 37304730,
        s: 1841489054,
    },
    SmallPrime {
        p: 2144894977,
        g: 1601434616,
        s: 157985831,
    },
    SmallPrime {
        p: 2144888833,
        g: 98749330,
        s: 2128592228,
    },
    SmallPrime {
        p: 2144880641,
        g: 1772327002,
        s: 2076128344,
    },
    SmallPrime {
        p: 2144864257,
        g: 1404514762,
        s: 2029969964,
    },
    SmallPrime {
        p: 2144827393,
        g: 801236594,
        s: 406627220,
    },
    SmallPrime {
        p: 2144806913,
        g: 349217443,
        s: 1501080290,
    },
    SmallPrime {
        p: 2144796673,
        g: 1542656776,
        s: 2084736519,
    },
    SmallPrime {
        p: 2144778241,
        g: 1210734884,
        s: 1746416203,
    },
    SmallPrime {
        p: 2144759809,
        g: 1146598851,
        s: 716464489,
    },
    SmallPrime {
        p: 2144757761,
        g: 286328400,
        s: 1823728177,
    },
    SmallPrime {
        p: 2144729089,
        g: 1347555695,
        s: 1836644881,
    },
    SmallPrime {
        p: 2144727041,
        g: 1795703790,
        s: 520296412,
    },
    SmallPrime {
        p: 2144696321,
        g: 1302475157,
        s: 852964281,
    },
    SmallPrime {
        p: 2144667649,
        g: 1075877614,
        s: 504992927,
    },
    SmallPrime {
        p: 2144573441,
        g: 198765808,
        s: 1617144982,
    },
    SmallPrime {
        p: 2144555009,
        g: 321528767,
        s: 155821259,
    },
    SmallPrime {
        p: 2144550913,
        g: 814139516,
        s: 1819937644,
    },
    SmallPrime {
        p: 2144536577,
        g: 571143206,
        s: 962942255,
    },
    SmallPrime {
        p: 2144524289,
        g: 1746733766,
        s: 2471321,
    },
    SmallPrime {
        p: 2144512001,
        g: 1821415077,
        s: 124190939,
    },
    SmallPrime {
        p: 2144468993,
        g: 917871546,
        s: 1260072806,
    },
    SmallPrime {
        p: 2144458753,
        g: 378417981,
        s: 1569240563,
    },
    SmallPrime {
        p: 2144421889,
        g: 175229668,
        s: 1825620763,
    },
    SmallPrime {
        p: 2144409601,
        g: 1699216963,
        s: 351648117,
    },
    SmallPrime {
        p: 2144370689,
        g: 1071885991,
        s: 958186029,
    },
    SmallPrime {
        p: 2144348161,
        g: 1763151227,
        s: 540353574,
    },
    SmallPrime {
        p: 2144335873,
        g: 1060214804,
        s: 919598847,
    },
    SmallPrime {
        p: 2144329729,
        g: 663515846,
        s: 1448552668,
    },
    SmallPrime {
        p: 2144327681,
        g: 1057776305,
        s: 590222840,
    },
    SmallPrime {
        p: 2144309249,
        g: 1705149168,
        s: 1459294624,
    },
    SmallPrime {
        p: 2144296961,
        g: 325823721,
        s: 1649016934,
    },
    SmallPrime {
        p: 2144290817,
        g: 738775789,
        s: 447427206,
    },
    SmallPrime {
        p: 2144243713,
        g: 962347618,
        s: 893050215,
    },
    SmallPrime {
        p: 2144237569,
        g: 1655257077,
        s: 900860862,
    },
    SmallPrime {
        p: 2144161793,
        g: 242206694,
        s: 1567868672,
    },
    SmallPrime {
        p: 2144155649,
        g: 769415308,
        s: 1247993134,
    },
    SmallPrime {
        p: 2144137217,
        g: 320492023,
        s: 515841070,
    },
    SmallPrime {
        p: 2144120833,
        g: 1639388522,
        s: 770877302,
    },
    SmallPrime {
        p: 2144071681,
        g: 1761785233,
        s: 964296120,
    },
    SmallPrime {
        p: 2144065537,
        g: 419817825,
        s: 204564472,
    },
    SmallPrime {
        p: 2144028673,
        g: 666050597,
        s: 2091019760,
    },
    SmallPrime {
        p: 2144010241,
        g: 1413657615,
        s: 1518702610,
    },
    SmallPrime {
        p: 2143952897,
        g: 1238327946,
        s: 475672271,
    },
    SmallPrime {
        p: 2143940609,
        g: 307063413,
        s: 1176750846,
    },
    SmallPrime {
        p: 2143918081,
        g: 2062905559,
        s: 786785803,
    },
    SmallPrime {
        p: 2143899649,
        g: 1338112849,
        s: 1562292083,
    },
    SmallPrime {
        p: 2143891457,
        g: 68149545,
        s: 87166451,
    },
    SmallPrime {
        p: 2143885313,
        g: 921750778,
        s: 394460854,
    },
    SmallPrime {
        p: 2143854593,
        g: 719766593,
        s: 133877196,
    },
    SmallPrime {
        p: 2143836161,
        g: 1149399850,
        s: 1861591875,
    },
    SmallPrime {
        p: 2143762433,
        g: 1848739366,
        s: 1335934145,
    },
    SmallPrime {
        p: 2143756289,
        g: 1326674710,
        s: 102999236,
    },
    SmallPrime {
        p: 2143713281,
        g: 808061791,
        s: 1156900308,
    },
    SmallPrime {
        p: 2143690753,
        g: 388399459,
        s: 1926468019,
    },
    SmallPrime {
        p: 2143670273,
        g: 1427891374,
        s: 1756689401,
    },
    SmallPrime {
        p: 2143666177,
        g: 1912173949,
        s: 986629565,
    },
    SmallPrime {
        p: 2143645697,
        g: 2041160111,
        s: 371842865,
    },
    SmallPrime {
        p: 2143641601,
        g: 1279906897,
        s: 2023974350,
    },
    SmallPrime {
        p: 2143635457,
        g: 720473174,
        s: 1389027526,
    },
    SmallPrime {
        p: 2143621121,
        g: 1298309455,
        s: 1732632006,
    },
    SmallPrime {
        p: 2143598593,
        g: 1548762216,
        s: 1825417506,
    },
    SmallPrime {
        p: 2143567873,
        g: 620475784,
        s: 1073787233,
    },
    SmallPrime {
        p: 2143561729,
        g: 1932954575,
        s: 949167309,
    },
    SmallPrime {
        p: 2143553537,
        g: 354315656,
        s: 1652037534,
    },
    SmallPrime {
        p: 2143541249,
        g: 577424288,
        s: 1097027618,
    },
    SmallPrime {
        p: 2143531009,
        g: 357862822,
        s: 478640055,
    },
    SmallPrime {
        p: 2143522817,
        g: 2017706025,
        s: 1550531668,
    },
    SmallPrime {
        p: 2143506433,
        g: 2078127419,
        s: 1824320165,
    },
    SmallPrime {
        p: 2143488001,
        g: 613475285,
        s: 1604011510,
    },
    SmallPrime {
        p: 2143469569,
        g: 1466594987,
        s: 502095196,
    },
    SmallPrime {
        p: 2143426561,
        g: 1115430331,
        s: 1044637111,
    },
    SmallPrime {
        p: 2143383553,
        g: 9778045,
        s: 1902463734,
    },
    SmallPrime {
        p: 2143377409,
        g: 1557401276,
        s: 2056861771,
    },
    SmallPrime {
        p: 2143363073,
        g: 652036455,
        s: 1965915971,
    },
    SmallPrime {
        p: 2143260673,
        g: 1464581171,
        s: 1523257541,
    },
    SmallPrime {
        p: 2143246337,
        g: 1876119649,
        s: 764541916,
    },
    SmallPrime {
        p: 2143209473,
        g: 1614992673,
        s: 1920672844,
    },
    SmallPrime {
        p: 2143203329,
        g: 981052047,
        s: 2049774209,
    },
    SmallPrime {
        p: 2143160321,
        g: 1847355533,
        s: 728535665,
    },
    SmallPrime {
        p: 2143129601,
        g: 965558457,
        s: 603052992,
    },
    SmallPrime {
        p: 2143123457,
        g: 2140817191,
        s: 8348679,
    },
    SmallPrime {
        p: 2143100929,
        g: 1547263683,
        s: 694209023,
    },
    SmallPrime {
        p: 2143092737,
        g: 643459066,
        s: 1979934533,
    },
    SmallPrime {
        p: 2143082497,
        g: 188603778,
        s: 2026175670,
    },
    SmallPrime {
        p: 2143062017,
        g: 1657329695,
        s: 377451099,
    },
    SmallPrime {
        p: 2143051777,
        g: 114967950,
        s: 979255473,
    },
    SmallPrime {
        p: 2143025153,
        g: 1698431342,
        s: 1449196896,
    },
    SmallPrime {
        p: 2143006721,
        g: 1862741675,
        s: 1739650365,
    },
    SmallPrime {
        p: 2142996481,
        g: 756660457,
        s: 996160050,
    },
    SmallPrime {
        p: 2142976001,
        g: 927864010,
        s: 1166847574,
    },
    SmallPrime {
        p: 2142965761,
        g: 905070557,
        s: 661974566,
    },
    SmallPrime {
        p: 2142916609,
        g: 40932754,
        s: 1787161127,
    },
    SmallPrime {
        p: 2142892033,
        g: 1987985648,
        s: 675335382,
    },
    SmallPrime {
        p: 2142885889,
        g: 797497211,
        s: 1323096997,
    },
    SmallPrime {
        p: 2142871553,
        g: 2068025830,
        s: 1411877159,
    },
    SmallPrime {
        p: 2142861313,
        g: 1217177090,
        s: 1438410687,
    },
    SmallPrime {
        p: 2142830593,
        g: 409906375,
        s: 1767860634,
    },
    SmallPrime {
        p: 2142803969,
        g: 1197788993,
        s: 359782919,
    },
    SmallPrime {
        p: 2142785537,
        g: 643817365,
        s: 513932862,
    },
    SmallPrime {
        p: 2142779393,
        g: 1717046338,
        s: 218943121,
    },
    SmallPrime {
        p: 2142724097,
        g: 89336830,
        s: 416687049,
    },
    SmallPrime {
        p: 2142707713,
        g: 5944581,
        s: 1356813523,
    },
    SmallPrime {
        p: 2142658561,
        g: 887942135,
        s: 2074011722,
    },
    SmallPrime {
        p: 2142638081,
        g: 151851972,
        s: 1647339939,
    },
    SmallPrime {
        p: 2142564353,
        g: 1691505537,
        s: 1483107336,
    },
    SmallPrime {
        p: 2142533633,
        g: 1989920200,
        s: 1135938817,
    },
    SmallPrime {
        p: 2142529537,
        g: 959263126,
        s: 1531961857,
    },
    SmallPrime {
        p: 2142527489,
        g: 453251129,
        s: 1725566162,
    },
    SmallPrime {
        p: 2142502913,
        g: 1536028102,
        s: 182053257,
    },
    SmallPrime {
        p: 2142498817,
        g: 570138730,
        s: 701443447,
    },
    SmallPrime {
        p: 2142416897,
        g: 326965800,
        s: 411931819,
    },
    SmallPrime {
        p: 2142363649,
        g: 1675665410,
        s: 1517191733,
    },
    SmallPrime {
        p: 2142351361,
        g: 968529566,
        s: 1575712703,
    },
    SmallPrime {
        p: 2142330881,
        g: 1384953238,
        s: 1769087884,
    },
    SmallPrime {
        p: 2142314497,
        g: 1977173242,
        s: 1833745524,
    },
    SmallPrime {
        p: 2142289921,
        g: 95082313,
        s: 1714775493,
    },
    SmallPrime {
        p: 2142283777,
        g: 109377615,
        s: 1070584533,
    },
    SmallPrime {
        p: 2142277633,
        g: 16960510,
        s: 702157145,
    },
    SmallPrime {
        p: 2142263297,
        g: 553850819,
        s: 431364395,
    },
    SmallPrime {
        p: 2142208001,
        g: 241466367,
        s: 2053967982,
    },
    SmallPrime {
        p: 2142164993,
        g: 1795661326,
        s: 1031836848,
    },
    SmallPrime {
        p: 2142097409,
        g: 1212530046,
        s: 712772031,
    },
    SmallPrime {
        p: 2142087169,
        g: 1763869720,
        s: 822276067,
    },
    SmallPrime {
        p: 2142078977,
        g: 644065713,
        s: 1765268066,
    },
    SmallPrime {
        p: 2142074881,
        g: 112671944,
        s: 643204925,
    },
    SmallPrime {
        p: 2142044161,
        g: 1387785471,
        s: 1297890174,
    },
    SmallPrime {
        p: 2142025729,
        g: 783885537,
        s: 1000425730,
    },
    SmallPrime {
        p: 2142011393,
        g: 905662232,
        s: 1679401033,
    },
    SmallPrime {
        p: 2141974529,
        g: 799788433,
        s: 468119557,
    },
    SmallPrime {
        p: 2141943809,
        g: 1932544124,
        s: 449305555,
    },
    SmallPrime {
        p: 2141933569,
        g: 1527403256,
        s: 841867925,
    },
    SmallPrime {
        p: 2141931521,
        g: 1247076451,
        s: 743823916,
    },
    SmallPrime {
        p: 2141902849,
        g: 1199660531,
        s: 401687910,
    },
    SmallPrime {
        p: 2141890561,
        g: 150132350,
        s: 1720336972,
    },
    SmallPrime {
        p: 2141857793,
        g: 1287438162,
        s: 663880489,
    },
    SmallPrime {
        p: 2141833217,
        g: 618017731,
        s: 1819208266,
    },
    SmallPrime {
        p: 2141820929,
        g: 999578638,
        s: 1403090096,
    },
    SmallPrime {
        p: 2141786113,
        g: 81834325,
        s: 1523542501,
    },
    SmallPrime {
        p: 2141771777,
        g: 120001928,
        s: 463556492,
    },
    SmallPrime {
        p: 2141759489,
        g: 122455485,
        s: 2124928282,
    },
    SmallPrime {
        p: 2141749249,
        g: 141986041,
        s: 940339153,
    },
    SmallPrime {
        p: 2141685761,
        g: 889088734,
        s: 477141499,
    },
    SmallPrime {
        p: 2141673473,
        g: 324212681,
        s: 1122558298,
    },
    SmallPrime {
        p: 2141669377,
        g: 1175806187,
        s: 1373818177,
    },
    SmallPrime {
        p: 2141655041,
        g: 1113654822,
        s: 296887082,
    },
    SmallPrime {
        p: 2141587457,
        g: 991103258,
        s: 1585913875,
    },
    SmallPrime {
        p: 2141583361,
        g: 1401451409,
        s: 1802457360,
    },
    SmallPrime {
        p: 2141575169,
        g: 1571977166,
        s: 712760980,
    },
    SmallPrime {
        p: 2141546497,
        g: 1107849376,
        s: 1250270109,
    },
    SmallPrime {
        p: 2141515777,
        g: 196544219,
        s: 356001130,
    },
    SmallPrime {
        p: 2141495297,
        g: 1733571506,
        s: 1060744866,
    },
    SmallPrime {
        p: 2141483009,
        g: 321552363,
        s: 1168297026,
    },
    SmallPrime {
        p: 2141458433,
        g: 505818251,
        s: 733225819,
    },
    SmallPrime {
        p: 2141360129,
        g: 1026840098,
        s: 948342276,
    },
    SmallPrime {
        p: 2141325313,
        g: 945133744,
        s: 2129965998,
    },
    SmallPrime {
        p: 2141317121,
        g: 1871100260,
        s: 1843844634,
    },
    SmallPrime {
        p: 2141286401,
        g: 1790639498,
        s: 1750465696,
    },
    SmallPrime {
        p: 2141267969,
        g: 1376858592,
        s: 186160720,
    },
    SmallPrime {
        p: 2141255681,
        g: 2129698296,
        s: 1876677959,
    },
    SmallPrime {
        p: 2141243393,
        g: 2138900688,
        s: 1340009628,
    },
    SmallPrime {
        p: 2141214721,
        g: 1933049835,
        s: 1087819477,
    },
    SmallPrime {
        p: 2141212673,
        g: 1898664939,
        s: 1786328049,
    },
    SmallPrime {
        p: 2141202433,
        g: 990234828,
        s: 940682169,
    },
    SmallPrime {
        p: 2141175809,
        g: 1406392421,
        s: 993089586,
    },
    SmallPrime {
        p: 2141165569,
        g: 1263518371,
        s: 289019479,
    },
    SmallPrime {
        p: 2141073409,
        g: 1485624211,
        s: 507864514,
    },
    SmallPrime {
        p: 2141052929,
        g: 1885134788,
        s: 311252465,
    },
    SmallPrime {
        p: 2141040641,
        g: 1285021247,
        s: 280941862,
    },
    SmallPrime {
        p: 2141028353,
        g: 1527610374,
        s: 375035110,
    },
    SmallPrime {
        p: 2141011969,
        g: 1400626168,
        s: 164696620,
    },
    SmallPrime {
        p: 2140999681,
        g: 632959608,
        s: 966175067,
    },
    SmallPrime {
        p: 2140997633,
        g: 2045628978,
        s: 1290889438,
    },
    SmallPrime {
        p: 2140993537,
        g: 1412755491,
        s: 375366253,
    },
    SmallPrime {
        p: 2140942337,
        g: 719477232,
        s: 785367828,
    },
    SmallPrime {
        p: 2140925953,
        g: 45224252,
        s: 836552317,
    },
    SmallPrime {
        p: 2140917761,
        g: 1157376588,
        s: 1001839569,
    },
    SmallPrime {
        p: 2140887041,
        g: 278480752,
        s: 2098732796,
    },
    SmallPrime {
        p: 2140837889,
        g: 1663139953,
        s: 924094810,
    },
    SmallPrime {
        p: 2140788737,
        g: 802501511,
        s: 2045368990,
    },
    SmallPrime {
        p: 2140766209,
        g: 1820083885,
        s: 1800295504,
    },
    SmallPrime {
        p: 2140764161,
        g: 1169561905,
        s: 2106792035,
    },
    SmallPrime {
        p: 2140696577,
        g: 127781498,
        s: 1885987531,
    },
    SmallPrime {
        p: 2140684289,
        g: 16014477,
        s: 1098116827,
    },
    SmallPrime {
        p: 2140653569,
        g: 665960598,
        s: 1796728247,
    },
];

#[derive(Clone)]
pub(crate) struct DeepestNtruSolution {
    #[cfg(test)]
    pub(crate) resultant_f: Vec<u32>,
    #[cfg(test)]
    pub(crate) resultant_g: Vec<u32>,
    pub(crate) capital_f: Vec<u32>,
    pub(crate) capital_g: Vec<u32>,
}

#[derive(Clone)]
pub(crate) struct IntermediateNtruSolution {
    pub(crate) reduced_f: Vec<u32>,
    pub(crate) reduced_g: Vec<u32>,
    #[cfg(test)]
    pub(crate) word_len: usize,
}

const FPR_PTWO31M1: Fpr = 2_147_483_647.0;
const FPR_MTWO31M1: Fpr = -2_147_483_647.0;
const FPR_PTWO63M1: Fpr = 9_223_372_036_854_775_807.0;
const FPR_MTWO63M1: Fpr = -9_223_372_036_854_775_807.0;

fn scale_factor_pow2(mut dc: i32) -> Fpr {
    let mut pt = 0.5;
    if dc < 0 {
        dc = -dc;
        pt = 2.0;
    }
    let mut pdc = 1.0;
    while dc != 0 {
        if (dc & 1) != 0 {
            pdc = fpr_mul(pdc, pt);
        }
        dc >>= 1;
        pt = fpr_sqr(pt);
    }
    pdc
}

fn extract_top_words(
    src: &[u32],
    stride: usize,
    active_len: usize,
    take: usize,
    logn: usize,
) -> Vec<u32> {
    let n = 1usize << logn;
    let mut out = vec![0u32; n * take];
    for u in 0..n {
        let src_off = u * stride + (active_len - take);
        let dst_off = u * take;
        out[dst_off..dst_off + take].copy_from_slice(&src[src_off..src_off + take]);
    }
    out
}

fn poly_div_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: usize) {
    let hn = (1usize << logn) >> 1;
    for u in 0..hn {
        let inv = 1.0 / b[u];
        a[u] *= inv;
        a[u + hn] *= inv;
    }
}

fn make_fg_step(data: &[u32], logn: usize, depth: usize, in_ntt: bool, out_ntt: bool) -> Vec<u32> {
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth];
    let tlen = MAX_BL_SMALL[depth + 1];
    debug_assert_eq!(data.len(), 2 * n * slen);

    let (fs_in, gs_in) = data.split_at(n * slen);
    let mut fd = vec![0u32; hn * tlen];
    let mut gd = vec![0u32; hn * tlen];
    let mut fs = fs_in.to_vec();
    let mut gs = gs_in.to_vec();
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    let mut t1 = vec![0u32; n];

    for u in 0..slen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        for v in 0..n {
            t1[v] = fs[v * slen + u];
        }
        if !in_ntt {
            modp_ntt2_ext(&mut t1, 1, &gm, logn, p, p0i);
        }
        for v in 0..hn {
            let w0 = t1[(v << 1) + 0];
            let w1 = t1[(v << 1) + 1];
            fd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(&mut fs[u..], slen, &igm, logn, p, p0i);
        }

        for v in 0..n {
            t1[v] = gs[v * slen + u];
        }
        if !in_ntt {
            modp_ntt2_ext(&mut t1, 1, &gm, logn, p, p0i);
        }
        for v in 0..hn {
            let w0 = t1[(v << 1) + 0];
            let w1 = t1[(v << 1) + 1];
            gd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(&mut gs[u..], slen, &igm, logn, p, p0i);
        }

        if !out_ntt {
            modp_intt2_ext(&mut fd[u..], tlen, &igm, logn - 1, p, p0i);
            modp_intt2_ext(&mut gd[u..], tlen, &igm, logn - 1, p, p0i);
        }
    }

    let mut tmp = vec![0u32; slen.max(n)];
    zint_rebuild_crt(
        &mut fs,
        slen,
        slen,
        n,
        &SMALL_PRIMES[..slen],
        true,
        &mut tmp[..slen],
    );
    zint_rebuild_crt(
        &mut gs,
        slen,
        slen,
        n,
        &SMALL_PRIMES[..slen],
        true,
        &mut tmp[..slen],
    );

    for u in slen..tlen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(slen as u32, p, p0i, r2);
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        for v in 0..n {
            let x = &fs[v * slen..(v + 1) * slen];
            t1[v] = zint_mod_small_signed(x, p, p0i, r2, rx);
        }
        modp_ntt2_ext(&mut t1, 1, &gm, logn, p, p0i);
        for v in 0..hn {
            let w0 = t1[(v << 1) + 0];
            let w1 = t1[(v << 1) + 1];
            fd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }

        for v in 0..n {
            let x = &gs[v * slen..(v + 1) * slen];
            t1[v] = zint_mod_small_signed(x, p, p0i, r2, rx);
        }
        modp_ntt2_ext(&mut t1, 1, &gm, logn, p, p0i);
        for v in 0..hn {
            let w0 = t1[(v << 1) + 0];
            let w1 = t1[(v << 1) + 1];
            gd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }

        if !out_ntt {
            modp_intt2_ext(&mut fd[u..], tlen, &igm, logn - 1, p, p0i);
            modp_intt2_ext(&mut gd[u..], tlen, &igm, logn - 1, p, p0i);
        }
    }

    let mut out = fd;
    out.extend_from_slice(&gd);
    out
}

pub(crate) fn make_fg(f: &[i8], g: &[i8], logn: usize, depth: usize, out_ntt: bool) -> Vec<u32> {
    let n = 1usize << logn;
    debug_assert_eq!(f.len(), n);
    debug_assert_eq!(g.len(), n);
    debug_assert!(depth <= logn);

    let p0 = SMALL_PRIMES[0].p;
    let mut data = vec![0u32; 2 * n];
    for u in 0..n {
        data[u] = modp_set(f[u] as i32, p0);
        data[n + u] = modp_set(g[u] as i32, p0);
    }

    if depth == 0 && out_ntt {
        let p = SMALL_PRIMES[0].p;
        let p0i = modp_ninv31(p);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, SMALL_PRIMES[0].g, p, p0i);
        modp_ntt2_ext(&mut data[..n], 1, &gm, logn, p, p0i);
        modp_ntt2_ext(&mut data[n..], 1, &gm, logn, p, p0i);
        return data;
    }

    for d in 0..depth {
        data = make_fg_step(&data, logn - d, d, d != 0, (d + 1) < depth || out_ntt);
    }
    data
}

pub(crate) fn solve_ntru_deepest(
    logn_top: usize,
    f: &[i8],
    g: &[i8],
) -> Option<DeepestNtruSolution> {
    let len = *MAX_BL_SMALL.get(logn_top)?;
    let mut fg = make_fg(f, g, logn_top, logn_top, false);
    let mut tmp_crt = vec![0u32; len];
    zint_rebuild_crt(
        &mut fg,
        len,
        len,
        2,
        &SMALL_PRIMES[..len],
        false,
        &mut tmp_crt,
    );

    let resultant_f = fg[..len].to_vec();
    let resultant_g = fg[len..(2 * len)].to_vec();

    let mut capital_f = vec![0u32; len];
    let mut capital_g = vec![0u32; len];
    let mut tmp_bezout = vec![0u32; len * 4];
    if !zint_bezout(
        &mut capital_g,
        &mut capital_f,
        &resultant_f,
        &resultant_g,
        &mut tmp_bezout,
    ) {
        return None;
    }

    if zint_mul_small(&mut capital_f, 12289) != 0 || zint_mul_small(&mut capital_g, 12289) != 0 {
        return None;
    }

    Some(DeepestNtruSolution {
        #[cfg(test)]
        resultant_f,
        #[cfg(test)]
        resultant_g,
        capital_f,
        capital_g,
    })
}

pub(crate) fn solve_ntru_intermediate(
    logn_top: usize,
    f: &[i8],
    g: &[i8],
    depth: usize,
    deeper_f: &[u32],
    deeper_g: &[u32],
) -> Option<IntermediateNtruSolution> {
    if depth == 0 || depth >= logn_top {
        return None;
    }
    let logn = logn_top - depth;
    if logn == 0 || depth >= MAX_BL_LARGE.len() {
        return None;
    }
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = *MAX_BL_SMALL.get(depth)?;
    let dlen = *MAX_BL_SMALL.get(depth + 1)?;
    let llen = *MAX_BL_LARGE.get(depth)?;
    if deeper_f.len() != hn * dlen || deeper_g.len() != hn * dlen {
        return None;
    }

    let mut fd_mod = vec![0u32; hn * llen];
    let mut gd_mod = vec![0u32; hn * llen];
    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        for v in 0..hn {
            fd_mod[v * llen + u] =
                zint_mod_small_signed(&deeper_f[v * dlen..(v + 1) * dlen], p, p0i, r2, rx);
            gd_mod[v * llen + u] =
                zint_mod_small_signed(&deeper_g[v * dlen..(v + 1) * dlen], p, p0i, r2, rx);
        }
    }

    let fg_ntt = make_fg(f, g, logn_top, depth, true);
    let mut ft = fg_ntt[..n * slen].to_vec();
    let mut gt = fg_ntt[n * slen..].to_vec();
    let mut out_f = vec![0u32; n * llen];
    let mut out_g = vec![0u32; n * llen];
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    let mut fx = vec![0u32; n];
    let mut gx = vec![0u32; n];
    let mut fp = vec![0u32; hn];
    let mut gp = vec![0u32; hn];
    let mut tmp_crt = vec![0u32; llen.max(n)];

    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);

        if u == slen {
            zint_rebuild_crt(
                &mut ft,
                slen,
                slen,
                n,
                &SMALL_PRIMES[..slen],
                true,
                &mut tmp_crt[..slen],
            );
            zint_rebuild_crt(
                &mut gt,
                slen,
                slen,
                n,
                &SMALL_PRIMES[..slen],
                true,
                &mut tmp_crt[..slen],
            );
        }

        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        if u < slen {
            for v in 0..n {
                fx[v] = ft[v * slen + u];
                gx[v] = gt[v * slen + u];
            }
            modp_intt2_ext(&mut ft[u..], slen, &igm, logn, p, p0i);
            modp_intt2_ext(&mut gt[u..], slen, &igm, logn, p, p0i);
        } else {
            let rx = modp_rx(slen as u32, p, p0i, r2);
            for v in 0..n {
                fx[v] = zint_mod_small_signed(&ft[v * slen..(v + 1) * slen], p, p0i, r2, rx);
                gx[v] = zint_mod_small_signed(&gt[v * slen..(v + 1) * slen], p, p0i, r2, rx);
            }
            modp_ntt2_ext(&mut fx, 1, &gm, logn, p, p0i);
            modp_ntt2_ext(&mut gx, 1, &gm, logn, p, p0i);
        }

        for v in 0..hn {
            fp[v] = fd_mod[v * llen + u];
            gp[v] = gd_mod[v * llen + u];
        }
        modp_ntt2_ext(&mut fp, 1, &gm, logn - 1, p, p0i);
        modp_ntt2_ext(&mut gp, 1, &gm, logn - 1, p, p0i);

        for v in 0..hn {
            let ft_a = fx[(v << 1) + 0];
            let ft_b = fx[(v << 1) + 1];
            let gt_a = gx[(v << 1) + 0];
            let gt_b = gx[(v << 1) + 1];
            let mfp = modp_montymul(fp[v], r2, p, p0i);
            let mgp = modp_montymul(gp[v], r2, p, p0i);
            out_f[(v << 1) * llen + u] = modp_montymul(gt_b, mfp, p, p0i);
            out_f[((v << 1) + 1) * llen + u] = modp_montymul(gt_a, mfp, p, p0i);
            out_g[(v << 1) * llen + u] = modp_montymul(ft_b, mgp, p, p0i);
            out_g[((v << 1) + 1) * llen + u] = modp_montymul(ft_a, mgp, p, p0i);
        }
        modp_intt2_ext(&mut out_f[u..], llen, &igm, logn, p, p0i);
        modp_intt2_ext(&mut out_g[u..], llen, &igm, logn, p, p0i);
    }

    zint_rebuild_crt(
        &mut out_f,
        llen,
        llen,
        n,
        &SMALL_PRIMES[..llen],
        true,
        &mut tmp_crt[..llen],
    );
    zint_rebuild_crt(
        &mut out_g,
        llen,
        llen,
        n,
        &SMALL_PRIMES[..llen],
        true,
        &mut tmp_crt[..llen],
    );

    let gm_table = GmTable::new();
    let mut rt1 = vec![0.0; n];
    let mut rt2 = vec![0.0; n];
    let mut rt3 = vec![0.0; n];
    let mut rt4 = vec![0.0; n];
    let mut rt5 = vec![0.0; n];
    let mut k = vec![0i32; n];
    let mut ntt_tmp = vec![0u32; n * (slen + 4)];

    let rlen_fg = slen.min(10);
    let ft_top = extract_top_words(&ft, slen, slen, rlen_fg, logn);
    let gt_top = extract_top_words(&gt, slen, slen, rlen_fg, logn);
    poly_big_to_fp(&mut rt3, &ft_top, rlen_fg, rlen_fg, logn);
    poly_big_to_fp(&mut rt4, &gt_top, rlen_fg, rlen_fg, logn);
    let scale_fg = 31 * (slen - rlen_fg) as i32;
    let minbl_fg = BITLENGTH[depth].avg - 6 * BITLENGTH[depth].std;
    let maxbl_fg = BITLENGTH[depth].avg + 6 * BITLENGTH[depth].std;

    fft(&mut rt3, logn, &gm_table);
    fft(&mut rt4, logn, &gm_table);
    poly_invnorm2_fft(&mut rt5, &rt3, &rt4, logn);
    poly_adj_fft(&mut rt3, logn);
    poly_adj_fft(&mut rt4, logn);

    let mut fg_len = llen;
    let mut maxbl_f_g = 31 * llen as i32;
    let mut scale_k = maxbl_f_g - minbl_fg;
    if scale_k < 0 {
        scale_k = 0;
    }

    loop {
        let rlen = fg_len.min(10);
        let scale_fg_big = 31 * (fg_len - rlen) as i32;
        let out_f_top = extract_top_words(&out_f, llen, fg_len, rlen, logn);
        let out_g_top = extract_top_words(&out_g, llen, fg_len, rlen, logn);
        poly_big_to_fp(&mut rt1, &out_f_top, rlen, rlen, logn);
        poly_big_to_fp(&mut rt2, &out_g_top, rlen, rlen, logn);

        fft(&mut rt1, logn, &gm_table);
        fft(&mut rt2, logn, &gm_table);
        poly_mul_fft(&mut rt1, &rt3, logn);
        poly_mul_fft(&mut rt2, &rt4, logn);
        poly_add(&mut rt2, &rt1);
        poly_mul_autoadj_fft(&mut rt2, &rt5, logn);
        ifft(&mut rt2, logn, &gm_table);

        let pdc = scale_factor_pow2(scale_k - scale_fg_big + scale_fg);
        for u in 0..n {
            let xv = fpr_mul(rt2[u], pdc);
            if !fpr_lt(FPR_MTWO31M1, xv) || !fpr_lt(xv, FPR_PTWO31M1) {
                return None;
            }
            k[u] = fpr_rint(xv) as i32;
        }

        let sch = (scale_k / 31) as u32;
        let scl = (scale_k % 31) as u32;
        if depth <= DEPTH_INT_FG {
            poly_sub_scaled_ntt(
                &mut out_f,
                fg_len,
                llen,
                &ft,
                slen,
                slen,
                &k,
                sch,
                scl,
                logn,
                &mut ntt_tmp,
            );
            poly_sub_scaled_ntt(
                &mut out_g,
                fg_len,
                llen,
                &gt,
                slen,
                slen,
                &k,
                sch,
                scl,
                logn,
                &mut ntt_tmp,
            );
        } else {
            poly_sub_scaled(
                &mut out_f, fg_len, llen, &ft, slen, slen, &k, sch, scl, logn,
            );
            poly_sub_scaled(
                &mut out_g, fg_len, llen, &gt, slen, slen, &k, sch, scl, logn,
            );
        }

        let new_maxbl_f_g = scale_k + maxbl_fg + 10;
        if new_maxbl_f_g < maxbl_f_g {
            maxbl_f_g = new_maxbl_f_g;
            if (fg_len as i32) * 31 >= maxbl_f_g + 31 {
                fg_len -= 1;
            }
        }

        if scale_k == 0 {
            break;
        }
        scale_k -= 25;
        if scale_k < 0 {
            scale_k = 0;
        }
    }

    if fg_len < slen {
        for u in 0..n {
            let base = u * llen;
            let sw_f = 0u32.wrapping_sub(out_f[base + fg_len - 1] >> 30) >> 1;
            for v in fg_len..slen {
                out_f[base + v] = sw_f;
            }
            let sw_g = 0u32.wrapping_sub(out_g[base + fg_len - 1] >> 30) >> 1;
            for v in fg_len..slen {
                out_g[base + v] = sw_g;
            }
        }
    }

    let mut reduced_f = vec![0u32; n * slen];
    let mut reduced_g = vec![0u32; n * slen];
    for u in 0..n {
        let src = u * llen;
        let dst = u * slen;
        reduced_f[dst..dst + slen].copy_from_slice(&out_f[src..src + slen]);
        reduced_g[dst..dst + slen].copy_from_slice(&out_g[src..src + slen]);
    }

    Some(IntermediateNtruSolution {
        reduced_f,
        reduced_g,
        #[cfg(test)]
        word_len: slen,
    })
}

pub(crate) fn solve_ntru_binary_depth1(
    logn_top: usize,
    f: &[i8],
    g: &[i8],
    deeper_f: &[u32],
    deeper_g: &[u32],
) -> Option<IntermediateNtruSolution> {
    if logn_top <= 2 {
        return None;
    }
    let depth = 1usize;
    let logn = logn_top - depth;
    let n_top = 1usize << logn_top;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth];
    let dlen = MAX_BL_SMALL[depth + 1];
    let llen = MAX_BL_LARGE[depth];
    if deeper_f.len() != hn * dlen || deeper_g.len() != hn * dlen {
        return None;
    }

    let mut fd_mod = vec![0u32; hn * llen];
    let mut gd_mod = vec![0u32; hn * llen];
    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        for v in 0..hn {
            fd_mod[v * llen + u] =
                zint_mod_small_signed(&deeper_f[v * dlen..(v + 1) * dlen], p, p0i, r2, rx);
            gd_mod[v * llen + u] =
                zint_mod_small_signed(&deeper_g[v * dlen..(v + 1) * dlen], p, p0i, r2, rx);
        }
    }

    let mut out_f = vec![0u32; n * llen];
    let mut out_g = vec![0u32; n * llen];
    let mut ft = vec![0u32; n * slen];
    let mut gt = vec![0u32; n * slen];
    let mut fx = vec![0u32; n_top];
    let mut gx = vec![0u32; n_top];
    let mut gm_top = vec![0u32; n_top];
    let mut igm_top = vec![0u32; n_top];
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    let mut fp = vec![0u32; hn];
    let mut gp = vec![0u32; hn];
    let mut tmp_crt = vec![0u32; llen];

    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);

        modp_mkgm2(&mut gm_top, &mut igm_top, logn_top, prime.g, p, p0i);
        for v in 0..n_top {
            fx[v] = modp_set(f[v] as i32, p);
            gx[v] = modp_set(g[v] as i32, p);
        }
        modp_ntt2_ext(&mut fx, 1, &gm_top, logn_top, p, p0i);
        modp_ntt2_ext(&mut gx, 1, &gm_top, logn_top, p, p0i);
        for e in ((logn + 1)..=logn_top).rev() {
            modp_poly_rec_res(&mut fx, e, p, p0i, r2);
            modp_poly_rec_res(&mut gx, e, p, p0i, r2);
        }

        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);
        for v in 0..hn {
            fp[v] = fd_mod[v * llen + u];
            gp[v] = gd_mod[v * llen + u];
        }
        modp_ntt2_ext(&mut fp, 1, &gm, logn - 1, p, p0i);
        modp_ntt2_ext(&mut gp, 1, &gm, logn - 1, p, p0i);

        for v in 0..hn {
            let ft_a = fx[v << 1];
            let ft_b = fx[(v << 1) + 1];
            let gt_a = gx[v << 1];
            let gt_b = gx[(v << 1) + 1];
            let mfp = modp_montymul(fp[v], r2, p, p0i);
            let mgp = modp_montymul(gp[v], r2, p, p0i);
            out_f[(v << 1) * llen + u] = modp_montymul(gt_b, mfp, p, p0i);
            out_f[((v << 1) + 1) * llen + u] = modp_montymul(gt_a, mfp, p, p0i);
            out_g[(v << 1) * llen + u] = modp_montymul(ft_b, mgp, p, p0i);
            out_g[((v << 1) + 1) * llen + u] = modp_montymul(ft_a, mgp, p, p0i);
        }
        modp_intt2_ext(&mut out_f[u..], llen, &igm, logn, p, p0i);
        modp_intt2_ext(&mut out_g[u..], llen, &igm, logn, p, p0i);

        if u < slen {
            let mut cur_fx = fx[..n].to_vec();
            let mut cur_gx = gx[..n].to_vec();
            modp_intt2_ext(&mut cur_fx, 1, &igm, logn, p, p0i);
            modp_intt2_ext(&mut cur_gx, 1, &igm, logn, p, p0i);
            for v in 0..n {
                ft[v * slen + u] = cur_fx[v];
                gt[v * slen + u] = cur_gx[v];
            }
        }
    }

    zint_rebuild_crt(
        &mut out_f,
        llen,
        llen,
        n,
        &SMALL_PRIMES[..llen],
        true,
        &mut tmp_crt[..llen],
    );
    zint_rebuild_crt(
        &mut out_g,
        llen,
        llen,
        n,
        &SMALL_PRIMES[..llen],
        true,
        &mut tmp_crt[..llen],
    );

    let fg_small = {
        let mut joined = ft.clone();
        joined.extend_from_slice(&gt);
        joined
    };
    let mut fg_small = fg_small;
    zint_rebuild_crt(
        &mut fg_small,
        slen,
        slen,
        2 * n,
        &SMALL_PRIMES[..slen],
        true,
        &mut tmp_crt[..slen],
    );
    ft.copy_from_slice(&fg_small[..n * slen]);
    gt.copy_from_slice(&fg_small[n * slen..]);

    let gm_table = GmTable::new();
    let mut rt1 = vec![0.0; n];
    let mut rt2 = vec![0.0; n];
    let mut rt3 = vec![0.0; n];
    let mut rt4 = vec![0.0; n];
    let mut rt5 = vec![0.0; n];
    let mut rt6 = vec![0.0; n];

    poly_big_to_fp(&mut rt1, &out_f, llen, llen, logn);
    poly_big_to_fp(&mut rt2, &out_g, llen, llen, logn);
    poly_big_to_fp(&mut rt3, &ft, slen, slen, logn);
    poly_big_to_fp(&mut rt4, &gt, slen, slen, logn);

    fft(&mut rt1, logn, &gm_table);
    fft(&mut rt2, logn, &gm_table);
    fft(&mut rt3, logn, &gm_table);
    fft(&mut rt4, logn, &gm_table);

    rt5.copy_from_slice(&rt1);
    poly_muladj_fft(&mut rt5, &rt3, logn);
    rt6.copy_from_slice(&rt2);
    poly_muladj_fft(&mut rt6, &rt4, logn);
    poly_add(&mut rt5, &rt6);
    poly_invnorm2_fft(&mut rt6, &rt3, &rt4, logn);
    poly_mul_autoadj_fft(&mut rt5, &rt6, logn);

    ifft(&mut rt5, logn, &gm_table);
    for value in &mut rt5 {
        let z = *value;
        if !fpr_lt(z, FPR_PTWO63M1) || !fpr_lt(FPR_MTWO63M1, z) {
            return None;
        }
        *value = fpr_rint(z) as Fpr;
    }
    fft(&mut rt5, logn, &gm_table);

    poly_mul_fft(&mut rt3, &rt5, logn);
    poly_mul_fft(&mut rt4, &rt5, logn);
    poly_sub(&mut rt1, &rt3);
    poly_sub(&mut rt2, &rt4);
    ifft(&mut rt1, logn, &gm_table);
    ifft(&mut rt2, logn, &gm_table);

    let mut reduced_f = vec![0u32; n];
    let mut reduced_g = vec![0u32; n];
    for u in 0..n {
        let f_word = fpr_rint(rt1[u]) as i32 as u32;
        let g_word = fpr_rint(rt2[u]) as i32 as u32;
        reduced_f[u] = f_word & 0x7FFF_FFFF;
        reduced_g[u] = g_word & 0x7FFF_FFFF;
    }

    Some(IntermediateNtruSolution {
        reduced_f,
        reduced_g,
        #[cfg(test)]
        word_len: 1,
    })
}

pub(crate) fn solve_ntru_binary_depth0(
    logn: usize,
    f: &[i8],
    g: &[i8],
    deeper_f: &[u32],
    deeper_g: &[u32],
) -> Option<IntermediateNtruSolution> {
    if logn <= 2 {
        return None;
    }
    let n = 1usize << logn;
    let hn = n >> 1;
    if deeper_f.len() != hn || deeper_g.len() != hn {
        return None;
    }

    let p = SMALL_PRIMES[0].p;
    let p0i = modp_ninv31(p);
    let r2 = modp_r2(p, p0i);
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    modp_mkgm2(&mut gm, &mut igm, logn, SMALL_PRIMES[0].g, p, p0i);

    let mut fp = vec![0u32; hn];
    let mut gp = vec![0u32; hn];
    for u in 0..hn {
        fp[u] = modp_set(zint_one_to_plain(&deeper_f[u..u + 1]), p);
        gp[u] = modp_set(zint_one_to_plain(&deeper_g[u..u + 1]), p);
    }
    modp_ntt2_ext(&mut fp, 1, &gm, logn - 1, p, p0i);
    modp_ntt2_ext(&mut gp, 1, &gm, logn - 1, p, p0i);

    let mut ft = vec![0u32; n];
    let mut gt = vec![0u32; n];
    for u in 0..n {
        ft[u] = modp_set(f[u] as i32, p);
        gt[u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2_ext(&mut ft, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut gt, 1, &gm, logn, p, p0i);

    let mut capital_f = vec![0u32; n];
    let mut capital_g = vec![0u32; n];
    for u in (0..n).step_by(2) {
        let ft_a = ft[u];
        let ft_b = ft[u + 1];
        let gt_a = gt[u];
        let gt_b = gt[u + 1];
        let mfp = modp_montymul(fp[u >> 1], r2, p, p0i);
        let mgp = modp_montymul(gp[u >> 1], r2, p, p0i);
        capital_f[u] = modp_montymul(gt_b, mfp, p, p0i);
        capital_f[u + 1] = modp_montymul(gt_a, mfp, p, p0i);
        capital_g[u] = modp_montymul(ft_b, mgp, p, p0i);
        capital_g[u + 1] = modp_montymul(ft_a, mgp, p, p0i);
    }
    modp_intt2_ext(&mut capital_f, 1, &igm, logn, p, p0i);
    modp_intt2_ext(&mut capital_g, 1, &igm, logn, p, p0i);

    let mut capital_f_ntt = capital_f.clone();
    let mut capital_g_ntt = capital_g.clone();
    modp_ntt2_ext(&mut capital_f_ntt, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut capital_g_ntt, 1, &gm, logn, p, p0i);

    let mut f_ntt = vec![0u32; n];
    let mut adj_f_ntt = vec![0u32; n];
    f_ntt[0] = modp_set(f[0] as i32, p);
    adj_f_ntt[0] = modp_set(f[0] as i32, p);
    for u in 1..n {
        f_ntt[u] = modp_set(f[u] as i32, p);
        adj_f_ntt[n - u] = modp_set(-(f[u] as i32), p);
    }
    modp_ntt2_ext(&mut f_ntt, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut adj_f_ntt, 1, &gm, logn, p, p0i);

    let mut num = vec![0u32; n];
    let mut den = vec![0u32; n];
    for u in 0..n {
        let w = modp_montymul(adj_f_ntt[u], r2, p, p0i);
        num[u] = modp_montymul(w, capital_f_ntt[u], p, p0i);
        den[u] = modp_montymul(w, f_ntt[u], p, p0i);
    }

    let mut g_ntt = vec![0u32; n];
    let mut adj_g_ntt = vec![0u32; n];
    g_ntt[0] = modp_set(g[0] as i32, p);
    adj_g_ntt[0] = modp_set(g[0] as i32, p);
    for u in 1..n {
        g_ntt[u] = modp_set(g[u] as i32, p);
        adj_g_ntt[n - u] = modp_set(-(g[u] as i32), p);
    }
    modp_ntt2_ext(&mut g_ntt, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut adj_g_ntt, 1, &gm, logn, p, p0i);

    for u in 0..n {
        let w = modp_montymul(adj_g_ntt[u], r2, p, p0i);
        num[u] = modp_add(num[u], modp_montymul(w, capital_g_ntt[u], p, p0i), p);
        den[u] = modp_add(den[u], modp_montymul(w, g_ntt[u], p, p0i), p);
    }

    modp_intt2_ext(&mut num, 1, &igm, logn, p, p0i);
    modp_intt2_ext(&mut den, 1, &igm, logn, p, p0i);
    let mut rt_num = vec![0.0; n];
    let mut rt_den = vec![0.0; n];
    for u in 0..n {
        rt_num[u] = modp_norm(num[u], p) as Fpr;
        rt_den[u] = modp_norm(den[u], p) as Fpr;
    }

    let gm_table = GmTable::new();
    fft(&mut rt_den, logn, &gm_table);
    fft(&mut rt_num, logn, &gm_table);
    poly_div_autoadj_fft(&mut rt_num, &rt_den, logn);
    ifft(&mut rt_num, logn, &gm_table);

    let mut k = vec![0u32; n];
    for u in 0..n {
        k[u] = modp_set(fpr_rint(rt_num[u]) as i32, p);
    }

    let mut k_ntt = k.clone();
    let mut f_top = vec![0u32; n];
    let mut g_top = vec![0u32; n];
    for u in 0..n {
        f_top[u] = modp_set(f[u] as i32, p);
        g_top[u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2_ext(&mut k_ntt, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut f_top, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut g_top, 1, &gm, logn, p, p0i);
    for u in 0..n {
        let kw = modp_montymul(k_ntt[u], r2, p, p0i);
        capital_f_ntt[u] = modp_sub(capital_f_ntt[u], modp_montymul(kw, f_top[u], p, p0i), p);
        capital_g_ntt[u] = modp_sub(capital_g_ntt[u], modp_montymul(kw, g_top[u], p, p0i), p);
    }

    modp_intt2_ext(&mut capital_f_ntt, 1, &igm, logn, p, p0i);
    modp_intt2_ext(&mut capital_g_ntt, 1, &igm, logn, p, p0i);
    let mut reduced_f = vec![0u32; n];
    let mut reduced_g = vec![0u32; n];
    for u in 0..n {
        reduced_f[u] = (modp_norm(capital_f_ntt[u], p) as u32) & 0x7FFF_FFFF;
        reduced_g[u] = (modp_norm(capital_g_ntt[u], p) as u32) & 0x7FFF_FFFF;
    }

    Some(IntermediateNtruSolution {
        reduced_f,
        reduced_g,
        #[cfg(test)]
        word_len: 1,
    })
}

pub(crate) fn solve_ntru(logn: usize, f: &[i8], g: &[i8], lim: i32) -> Option<(Vec<i8>, Vec<i8>)> {
    if logn <= 2 {
        return None;
    }

    let deepest = solve_ntru_deepest(logn, f, g)?;
    let mut reduced_f = deepest.capital_f;
    let mut reduced_g = deepest.capital_g;
    for depth in (2..logn).rev() {
        let solution = solve_ntru_intermediate(logn, f, g, depth, &reduced_f, &reduced_g)?;
        reduced_f = solution.reduced_f;
        reduced_g = solution.reduced_g;
    }

    let depth1 = solve_ntru_binary_depth1(logn, f, g, &reduced_f, &reduced_g)?;
    let depth0 = solve_ntru_binary_depth0(logn, f, g, &depth1.reduced_f, &depth1.reduced_g)?;

    let n = 1usize << logn;
    let mut capital_f = vec![0i8; n];
    let mut capital_g = vec![0i8; n];
    for u in 0..n {
        let fv = zint_one_to_plain(&depth0.reduced_f[u..u + 1]);
        let gv = zint_one_to_plain(&depth0.reduced_g[u..u + 1]);
        if fv < -lim || fv > lim || gv < -lim || gv > lim {
            return None;
        }
        capital_f[u] = fv as i8;
        capital_g[u] = gv as i8;
    }
    if !verify_ntru_equation_mod_prime(logn, f, g, &capital_f, &capital_g) {
        return None;
    }

    Some((capital_f, capital_g))
}

fn verify_ntru_equation_mod_prime(
    logn: usize,
    f: &[i8],
    g: &[i8],
    capital_f: &[i8],
    capital_g: &[i8],
) -> bool {
    let n = 1usize << logn;
    let prime = SMALL_PRIMES[0];
    let p = prime.p;
    let p0i = modp_ninv31(p);
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

    let mut ft = vec![0u32; n];
    let mut gt = vec![0u32; n];
    let mut capital_ft = vec![0u32; n];
    let mut capital_gt = vec![0u32; n];
    for u in 0..n {
        ft[u] = modp_set(f[u] as i32, p);
        gt[u] = modp_set(g[u] as i32, p);
        capital_ft[u] = modp_set(capital_f[u] as i32, p);
        capital_gt[u] = modp_set(capital_g[u] as i32, p);
    }

    modp_ntt2_ext(&mut ft, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut gt, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut capital_ft, 1, &gm, logn, p, p0i);
    modp_ntt2_ext(&mut capital_gt, 1, &gm, logn, p, p0i);

    let q = modp_montymul(12289, 1, p, p0i);
    for u in 0..n {
        let z = modp_sub(
            modp_montymul(ft[u], capital_gt[u], p, p0i),
            modp_montymul(gt[u], capital_ft[u], p, p0i),
            p,
        );
        if z != q {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::borrow::ToOwned;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    use crate::key_material::decode_signing_key;
    use crate::modp::{modp_mkgm2, modp_ninv31, modp_ntt2_ext, modp_r2, modp_rx, modp_set};
    use crate::params::{FALCON_1024, FALCON_512};
    use crate::zint::{
        zint_mod_small_signed, zint_mod_small_unsigned, zint_one_to_plain, zint_rebuild_crt,
    };

    use super::{
        make_fg, solve_ntru_binary_depth0, solve_ntru_binary_depth1, solve_ntru_deepest,
        solve_ntru_intermediate, MAX_BL_SMALL, SMALL_PRIMES,
    };

    fn coeffs_mod_prime(words: &[u32], word_len: usize, p: u32, p0i: u32, r2: u32) -> Vec<u32> {
        let rx = modp_rx(word_len as u32, p, p0i, r2);
        words
            .chunks_exact(word_len)
            .map(|coeff| zint_mod_small_signed(coeff, p, p0i, r2, rx))
            .collect()
    }

    fn negacyclic_product_mod_prime(a: &[u32], b: &[u32], p: u32) -> Vec<u32> {
        let n = a.len();
        let mut out = vec![0u32; n];
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let prod = ((ai as u64) * (bj as u64)) % p as u64;
                let idx = i + j;
                if idx < n {
                    out[idx] = ((out[idx] as u64 + prod) % p as u64) as u32;
                } else {
                    let dst = idx - n;
                    out[dst] = ((out[dst] as u64 + p as u64 - prod) % p as u64) as u32;
                }
            }
        }
        out
    }

    fn ref_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("workspace root")
            .join("ref")
    }

    fn ensure_reference_paths(label: &str, paths: &[PathBuf]) -> bool {
        if let Some(missing) = paths.iter().find(|path| !path.exists()) {
            std::eprintln!("skipping {label}: missing {}", missing.display());
            return false;
        }
        true
    }

    fn parse_rsp_entries(path: &Path) -> Vec<BTreeMap<String, String>> {
        let content = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", path.display());
        });

        let mut entries = Vec::new();
        let mut current = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                if current.contains_key("count") {
                    entries.push(core::mem::take(&mut current));
                }
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(" = ") {
                current.insert(key.to_owned(), value.to_owned());
            }
        }
        if current.contains_key("count") {
            entries.push(current);
        }
        entries
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string has odd length");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair).unwrap();
            bytes.push(u8::from_str_radix(text, 16).unwrap());
        }
        bytes
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct BezoutIterState {
        pa: i64,
        pb: i64,
        qa: i64,
        qb: i64,
        a_hi: u64,
        b_hi: u64,
        a_lo: u32,
        b_lo: u32,
        r: u32,
        a0: u32,
        a1: u32,
        b0: u32,
        b1: u32,
    }

    fn bezout_outer_iteration_states(x: &[u32], y: &[u32], rounds: usize) -> Vec<BezoutIterState> {
        let len = x.len();
        let mut a = x.to_vec();
        let mut b = y.to_vec();
        let mut out = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let mut c0 = u32::MAX;
            let mut c1 = u32::MAX;
            let mut a0 = 0u32;
            let mut a1 = 0u32;
            let mut b0 = 0u32;
            let mut b1 = 0u32;
            let mut j = len;
            while j > 0 {
                j -= 1;
                let aw = a[j];
                let bw = b[j];
                a0 ^= (a0 ^ aw) & c0;
                a1 ^= (a1 ^ aw) & c1;
                b0 ^= (b0 ^ bw) & c0;
                b1 ^= (b1 ^ bw) & c1;
                c1 = c0;
                c0 &= (((aw | bw).wrapping_add(0x7FFF_FFFF)) >> 31).wrapping_sub(1);
            }

            a1 |= a0 & c1;
            a0 &= !c1;
            b1 |= b0 & c1;
            b0 &= !c1;
            let mut a_hi = ((a0 as u64) << 31).wrapping_add(a1 as u64);
            let mut b_hi = ((b0 as u64) << 31).wrapping_add(b1 as u64);
            let mut a_lo = a[0];
            let mut b_lo = b[0];
            let mut pa = 1i64;
            let mut pb = 0i64;
            let mut qa = 0i64;
            let mut qb = 1i64;
            for i in 0..31 {
                let rz = b_hi.wrapping_sub(a_hi);
                let rt = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;
                let oa = (a_lo >> i) & 1;
                let ob = (b_lo >> i) & 1;
                let c_ab = oa & ob & rt;
                let c_ba = oa & ob & !rt;
                let c_a = c_ab | (oa ^ 1);
                let mask_ab_u32 = 0u32.wrapping_sub(c_ab);
                let mask_ba_u32 = 0u32.wrapping_sub(c_ba);
                let mask_ab_u64 = 0u64.wrapping_sub(c_ab as u64);
                let mask_ba_u64 = 0u64.wrapping_sub(c_ba as u64);
                let mask_ab_i64 = 0i64.wrapping_sub(c_ab as i64);
                let mask_ba_i64 = 0i64.wrapping_sub(c_ba as i64);

                a_lo = a_lo.wrapping_sub(b_lo & mask_ab_u32);
                a_hi = a_hi.wrapping_sub(b_hi & mask_ab_u64);
                pa = pa.wrapping_sub(qa & mask_ab_i64);
                pb = pb.wrapping_sub(qb & mask_ab_i64);
                b_lo = b_lo.wrapping_sub(a_lo & mask_ba_u32);
                b_hi = b_hi.wrapping_sub(a_hi & mask_ba_u64);
                qa = qa.wrapping_sub(pa & mask_ba_i64);
                qb = qb.wrapping_sub(pb & mask_ba_i64);
                a_lo = a_lo.wrapping_add(a_lo & c_a.wrapping_sub(1));
                pa = pa.wrapping_add(pa & ((c_a as i64).wrapping_sub(1)));
                pb = pb.wrapping_add(pb & ((c_a as i64).wrapping_sub(1)));
                a_hi ^= (a_hi ^ (a_hi >> 1)) & (0u64.wrapping_sub(c_a as u64));
                b_lo = b_lo.wrapping_add(b_lo & 0u32.wrapping_sub(c_a));
                qa = qa.wrapping_add(qa & 0i64.wrapping_sub(c_a as i64));
                qb = qb.wrapping_add(qb & 0i64.wrapping_sub(c_a as i64));
                b_hi ^= (b_hi ^ (b_hi >> 1)) & ((c_a as u64).wrapping_sub(1));
            }

            let r = crate::zint::zint_co_reduce(&mut a, &mut b, pa, pb, qa, qb);
            out.push(BezoutIterState {
                pa,
                pb,
                qa,
                qb,
                a_hi,
                b_hi,
                a_lo,
                b_lo,
                r,
                a0: a[0],
                a1: a[1],
                b0: b[0],
                b1: b[1],
            });
        }

        out
    }

    fn first_bezout_iteration_arrays(x: &[u32], y: &[u32]) -> (Vec<u32>, Vec<u32>) {
        let len = x.len();
        let mut a = x.to_vec();
        let mut b = y.to_vec();

        let mut c0 = u32::MAX;
        let mut c1 = u32::MAX;
        let mut a0 = 0u32;
        let mut a1 = 0u32;
        let mut b0 = 0u32;
        let mut b1 = 0u32;
        let mut j = len;
        while j > 0 {
            j -= 1;
            let aw = a[j];
            let bw = b[j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0x7FFF_FFFF)) >> 31).wrapping_sub(1);
        }

        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi = ((a0 as u64) << 31).wrapping_add(a1 as u64);
        let mut b_hi = ((b0 as u64) << 31).wrapping_add(b1 as u64);
        let mut a_lo = a[0];
        let mut b_lo = b[0];
        let mut pa = 1i64;
        let mut pb = 0i64;
        let mut qa = 0i64;
        let mut qb = 1i64;
        for i in 0..31 {
            let rz = b_hi.wrapping_sub(a_hi);
            let rt = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;
            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let c_ab = oa & ob & rt;
            let c_ba = oa & ob & !rt;
            let c_a = c_ab | (oa ^ 1);
            let mask_ab_u32 = 0u32.wrapping_sub(c_ab);
            let mask_ba_u32 = 0u32.wrapping_sub(c_ba);
            let mask_ab_u64 = 0u64.wrapping_sub(c_ab as u64);
            let mask_ba_u64 = 0u64.wrapping_sub(c_ba as u64);
            let mask_ab_i64 = 0i64.wrapping_sub(c_ab as i64);
            let mask_ba_i64 = 0i64.wrapping_sub(c_ba as i64);

            a_lo = a_lo.wrapping_sub(b_lo & mask_ab_u32);
            a_hi = a_hi.wrapping_sub(b_hi & mask_ab_u64);
            pa = pa.wrapping_sub(qa & mask_ab_i64);
            pb = pb.wrapping_sub(qb & mask_ab_i64);
            b_lo = b_lo.wrapping_sub(a_lo & mask_ba_u32);
            b_hi = b_hi.wrapping_sub(a_hi & mask_ba_u64);
            qa = qa.wrapping_sub(pa & mask_ba_i64);
            qb = qb.wrapping_sub(pb & mask_ba_i64);
            a_lo = a_lo.wrapping_add(a_lo & c_a.wrapping_sub(1));
            pa = pa.wrapping_add(pa & ((c_a as i64).wrapping_sub(1)));
            pb = pb.wrapping_add(pb & ((c_a as i64).wrapping_sub(1)));
            a_hi ^= (a_hi ^ (a_hi >> 1)) & (0u64.wrapping_sub(c_a as u64));
            b_lo = b_lo.wrapping_add(b_lo & 0u32.wrapping_sub(c_a));
            qa = qa.wrapping_add(qa & 0i64.wrapping_sub(c_a as i64));
            qb = qb.wrapping_add(qb & 0i64.wrapping_sub(c_a as i64));
            b_hi ^= (b_hi ^ (b_hi >> 1)) & ((c_a as u64).wrapping_sub(1));
        }

        crate::zint::zint_co_reduce(&mut a, &mut b, pa, pb, qa, qb);
        (a, b)
    }

    #[test]
    fn test_make_fg_matches_ntt_resultants_across_all_small_primes() {
        let cases = [
            ("falcon512-KAT.rsp", &FALCON_512),
            ("falcon1024-KAT.rsp", &FALCON_1024),
        ];
        let required_paths: Vec<PathBuf> = cases
            .iter()
            .map(|(file_name, _)| {
                ref_root()
                    .join("Falcon-FIPS_206")
                    .join("falcon-round3")
                    .join("KAT")
                    .join(file_name)
            })
            .collect();
        if !ensure_reference_paths("Falcon make_fg KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entry = parse_rsp_entries(&path)
                .into_iter()
                .next()
                .expect("missing KAT entry");
            let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
            let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
            let len = MAX_BL_SMALL[params.log_n];
            let mut fg = make_fg(&decoded.f, &decoded.g, params.log_n, params.log_n, false);
            let mut tmp_crt = vec![0u32; len];
            zint_rebuild_crt(
                &mut fg,
                len,
                len,
                2,
                &SMALL_PRIMES[..len],
                false,
                &mut tmp_crt,
            );
            let resultant_f = fg[..len].to_vec();
            let resultant_g = fg[len..(2 * len)].to_vec();
            for prime in SMALL_PRIMES.iter().take(len) {
                let p = prime.p;
                let p0i = modp_ninv31(p);
                let r2 = modp_r2(p, p0i);
                let mut gm = vec![0u32; params.n];
                let mut igm = vec![0u32; params.n];
                let mut ft = decoded
                    .f
                    .iter()
                    .map(|&coeff| modp_set(coeff as i32, p))
                    .collect::<Vec<_>>();
                let mut gt = decoded
                    .g
                    .iter()
                    .map(|&coeff| modp_set(coeff as i32, p))
                    .collect::<Vec<_>>();
                modp_mkgm2(&mut gm, &mut igm, params.log_n, prime.g, p, p0i);
                modp_ntt2_ext(&mut ft, 1, &gm, params.log_n, p, p0i);
                modp_ntt2_ext(&mut gt, 1, &gm, params.log_n, p, p0i);
                let want_f = ft.iter().fold(1u64, |acc, &w| (acc * w as u64) % p as u64) as u32;
                let want_g = gt.iter().fold(1u64, |acc, &w| (acc * w as u64) % p as u64) as u32;
                let got_f = zint_mod_small_unsigned(&resultant_f, p, p0i, r2);
                let got_g = zint_mod_small_unsigned(&resultant_g, p, p0i, r2);
                assert_eq!(got_f, want_f, "resultant_f mismatch mod {}", p);
                assert_eq!(got_g, want_g, "resultant_g mismatch mod {}", p);
            }
            assert_eq!(resultant_f[0] & 1, 1);
            assert_eq!(resultant_g[0] & 1, 1);
        }
    }

    #[test]
    fn test_first_bezout_iteration_matches_reference_c_oracle() {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join("falcon512-KAT.rsp");
        if !ensure_reference_paths("Falcon Bezout oracle check", std::slice::from_ref(&path)) {
            return;
        }
        let entry = parse_rsp_entries(&path)
            .into_iter()
            .next()
            .expect("missing KAT entry");
        let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
        let decoded = decode_signing_key(&sk_bytes, &FALCON_512).expect("decode signing key");
        let len = MAX_BL_SMALL[FALCON_512.log_n];
        let mut fg = make_fg(
            &decoded.f,
            &decoded.g,
            FALCON_512.log_n,
            FALCON_512.log_n,
            false,
        );
        let mut tmp_crt = vec![0u32; len];
        zint_rebuild_crt(
            &mut fg,
            len,
            len,
            2,
            &SMALL_PRIMES[..len],
            false,
            &mut tmp_crt,
        );
        let resultant_f = fg[..len].to_vec();
        let resultant_g = fg[len..(2 * len)].to_vec();
        let (_a_after_first, _b_after_first) =
            first_bezout_iteration_arrays(&resultant_f, &resultant_g);

        let states = bezout_outer_iteration_states(&resultant_f, &resultant_g, 4);
        assert_eq!(
            states,
            vec![
                BezoutIterState {
                    pa: 2147483648,
                    pb: 0,
                    qa: -1605177345,
                    qb: 1,
                    a_hi: 33270,
                    b_hi: 1974432626,
                    a_lo: 2147483648,
                    b_lo: 0,
                    r: 0,
                    a0: 28876801,
                    a1: 1829756161,
                    b0: 1036267676,
                    b1: 1707369903
                },
                BezoutIterState {
                    pa: 58697440,
                    pb: -904,
                    qa: -23142268,
                    qb: 393,
                    a_hi: 167985248158,
                    b_hi: 6005409208,
                    a_lo: 2147483648,
                    b_lo: 0,
                    r: 0,
                    a0: 3407457,
                    a1: 868974548,
                    b0: 1017655123,
                    b1: 187252636
                },
                BezoutIterState {
                    pa: 3192784,
                    pb: -89307376,
                    qa: -413325,
                    qb: 11562047,
                    a_hi: 6181,
                    b_hi: 1080,
                    a_lo: 2147483648,
                    b_lo: 2147483648,
                    r: 0,
                    a0: 2056713359,
                    a1: 879669991,
                    b0: 1519390621,
                    b1: 205781920
                },
                BezoutIterState {
                    pa: 2931691,
                    pb: -16767689,
                    qa: -1039190,
                    qb: 5944338,
                    a_hi: 655141,
                    b_hi: 559407,
                    a_lo: 2147483648,
                    b_lo: 2147483648,
                    r: 0,
                    a0: 326105216,
                    a1: 1541423039,
                    b0: 1415608215,
                    b1: 776017152
                },
            ]
        );
    }

    #[test]
    fn test_solve_ntru_deepest_succeeds_for_reference_kats() {
        let cases = [
            ("falcon512-KAT.rsp", &FALCON_512),
            ("falcon1024-KAT.rsp", &FALCON_1024),
        ];
        let required_paths: Vec<PathBuf> = cases
            .iter()
            .map(|(file_name, _)| {
                ref_root()
                    .join("Falcon-FIPS_206")
                    .join("falcon-round3")
                    .join("KAT")
                    .join(file_name)
            })
            .collect();
        if !ensure_reference_paths("Falcon solve_ntru deepest KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entry = parse_rsp_entries(&path)
                .into_iter()
                .next()
                .expect("missing KAT entry");
            let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
            let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
            let solution = super::solve_ntru_deepest(params.log_n, &decoded.f, &decoded.g)
                .expect("deepest NTRU solution");
            assert_eq!(solution.resultant_f.len(), MAX_BL_SMALL[params.log_n]);
            assert_eq!(solution.resultant_g.len(), MAX_BL_SMALL[params.log_n]);
            assert_eq!(solution.capital_f.len(), MAX_BL_SMALL[params.log_n]);
            assert_eq!(solution.capital_g.len(), MAX_BL_SMALL[params.log_n]);
            assert_eq!(solution.resultant_f[0] & 1, 1, "resultant_f must be odd");
            assert_eq!(solution.resultant_g[0] & 1, 1, "resultant_g must be odd");
        }
    }

    #[test]
    fn test_solve_ntru_intermediate_chain_reaches_depth2_for_reference_kats() {
        let cases = [
            ("falcon512-KAT.rsp", &FALCON_512),
            ("falcon1024-KAT.rsp", &FALCON_1024),
        ];
        let required_paths: Vec<PathBuf> = cases
            .iter()
            .map(|(file_name, _)| {
                ref_root()
                    .join("Falcon-FIPS_206")
                    .join("falcon-round3")
                    .join("KAT")
                    .join(file_name)
            })
            .collect();
        if !ensure_reference_paths("Falcon solve_ntru intermediate KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entry = parse_rsp_entries(&path)
                .into_iter()
                .next()
                .expect("missing KAT entry");
            let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
            let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
            let deepest =
                solve_ntru_deepest(params.log_n, &decoded.f, &decoded.g).expect("deepest solution");
            let mut reduced_f = deepest.capital_f.clone();
            let mut current_g = deepest.capital_g.clone();

            for depth in (2..params.log_n).rev() {
                let solution = solve_ntru_intermediate(
                    params.log_n,
                    &decoded.f,
                    &decoded.g,
                    depth,
                    &reduced_f,
                    &current_g,
                )
                .expect("solve intermediate");

                let logn = params.log_n - depth;
                let n = 1usize << logn;
                let slen = MAX_BL_SMALL[depth];
                assert_eq!(solution.word_len, slen);
                assert_eq!(solution.reduced_f.len(), n * slen);
                assert_eq!(solution.reduced_g.len(), n * slen);

                let mut fg = make_fg(&decoded.f, &decoded.g, params.log_n, depth, false);
                let mut tmp_crt = vec![0u32; slen];
                zint_rebuild_crt(
                    &mut fg,
                    slen,
                    slen,
                    2 * n,
                    &SMALL_PRIMES[..slen],
                    true,
                    &mut tmp_crt,
                );
                let base_f = &fg[..n * slen];
                let base_g = &fg[n * slen..];

                for prime in SMALL_PRIMES.iter().take(slen) {
                    let p = prime.p;
                    let p0i = modp_ninv31(p);
                    let r2 = modp_r2(p, p0i);
                    let f_mod = coeffs_mod_prime(base_f, slen, p, p0i, r2);
                    let g_mod = coeffs_mod_prime(base_g, slen, p, p0i, r2);
                    let f_big = coeffs_mod_prime(&solution.reduced_f, slen, p, p0i, r2);
                    let g_big = coeffs_mod_prime(&solution.reduced_g, slen, p, p0i, r2);
                    let lhs_f_g = negacyclic_product_mod_prime(&f_mod, &g_big, p);
                    let lhs_g_f = negacyclic_product_mod_prime(&g_mod, &f_big, p);

                    for u in 0..n {
                        let want = if u == 0 { 12289 % p } else { 0 };
                        let got =
                            ((lhs_f_g[u] as u64 + p as u64 - lhs_g_f[u] as u64) % p as u64) as u32;
                        assert_eq!(got, want, "depth {depth} coeff {u} mismatch mod {p}");
                    }
                }

                reduced_f = solution.reduced_f;
                current_g = solution.reduced_g;
            }
        }
    }

    #[test]
    fn test_solve_ntru_binary_depth1_reaches_reference_equation() {
        let cases = [
            ("falcon512-KAT.rsp", &FALCON_512),
            ("falcon1024-KAT.rsp", &FALCON_1024),
        ];
        let required_paths: Vec<PathBuf> = cases
            .iter()
            .map(|(file_name, _)| {
                ref_root()
                    .join("Falcon-FIPS_206")
                    .join("falcon-round3")
                    .join("KAT")
                    .join(file_name)
            })
            .collect();
        if !ensure_reference_paths("Falcon solve_ntru depth1 KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entry = parse_rsp_entries(&path)
                .into_iter()
                .next()
                .expect("missing KAT entry");
            let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
            let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
            let deepest =
                solve_ntru_deepest(params.log_n, &decoded.f, &decoded.g).expect("deepest solution");
            let mut reduced_f = deepest.capital_f.clone();
            let mut reduced_g = deepest.capital_g.clone();
            for depth in (2..params.log_n).rev() {
                let solution = solve_ntru_intermediate(
                    params.log_n,
                    &decoded.f,
                    &decoded.g,
                    depth,
                    &reduced_f,
                    &reduced_g,
                )
                .expect("solve intermediate");
                reduced_f = solution.reduced_f;
                reduced_g = solution.reduced_g;
            }

            let solution = solve_ntru_binary_depth1(
                params.log_n,
                &decoded.f,
                &decoded.g,
                &reduced_f,
                &reduced_g,
            )
            .expect("solve binary depth1");

            let depth = 1usize;
            let logn = params.log_n - depth;
            let n = 1usize << logn;
            let slen = MAX_BL_SMALL[depth];
            assert_eq!(solution.word_len, slen);
            assert_eq!(solution.reduced_f.len(), n * slen);
            assert_eq!(solution.reduced_g.len(), n * slen);

            let mut fg = make_fg(&decoded.f, &decoded.g, params.log_n, depth, false);
            let mut tmp_crt = vec![0u32; slen];
            zint_rebuild_crt(
                &mut fg,
                slen,
                slen,
                2 * n,
                &SMALL_PRIMES[..slen],
                true,
                &mut tmp_crt,
            );
            let base_f = &fg[..n * slen];
            let base_g = &fg[n * slen..];

            for prime in SMALL_PRIMES.iter().take(8) {
                let p = prime.p;
                let p0i = modp_ninv31(p);
                let r2 = modp_r2(p, p0i);
                let f_mod = coeffs_mod_prime(base_f, slen, p, p0i, r2);
                let g_mod = coeffs_mod_prime(base_g, slen, p, p0i, r2);
                let f_big = coeffs_mod_prime(&solution.reduced_f, slen, p, p0i, r2);
                let g_big = coeffs_mod_prime(&solution.reduced_g, slen, p, p0i, r2);
                let lhs_f_g = negacyclic_product_mod_prime(&f_mod, &g_big, p);
                let lhs_g_f = negacyclic_product_mod_prime(&g_mod, &f_big, p);

                for u in 0..n {
                    let want = if u == 0 { 12289 % p } else { 0 };
                    let got =
                        ((lhs_f_g[u] as u64 + p as u64 - lhs_g_f[u] as u64) % p as u64) as u32;
                    assert_eq!(got, want, "binary depth1 coeff {u} mismatch mod {p}");
                }
            }
        }
    }

    #[test]
    fn test_solve_ntru_binary_depth0_matches_reference_private_key() {
        let cases = [
            ("falcon512-KAT.rsp", &FALCON_512),
            ("falcon1024-KAT.rsp", &FALCON_1024),
        ];
        let required_paths: Vec<PathBuf> = cases
            .iter()
            .map(|(file_name, _)| {
                ref_root()
                    .join("Falcon-FIPS_206")
                    .join("falcon-round3")
                    .join("KAT")
                    .join(file_name)
            })
            .collect();
        if !ensure_reference_paths("Falcon solve_ntru depth0 KATs", &required_paths) {
            return;
        }

        for (file_name, params) in cases {
            let path = ref_root()
                .join("Falcon-FIPS_206")
                .join("falcon-round3")
                .join("KAT")
                .join(file_name);
            let entry = parse_rsp_entries(&path)
                .into_iter()
                .next()
                .expect("missing KAT entry");
            let sk_bytes = hex_decode(entry.get("sk").expect("missing sk"));
            let decoded = decode_signing_key(&sk_bytes, params).expect("decode signing key");
            let deepest =
                solve_ntru_deepest(params.log_n, &decoded.f, &decoded.g).expect("deepest solution");
            let mut reduced_f = deepest.capital_f.clone();
            let mut reduced_g = deepest.capital_g.clone();
            for depth in (2..params.log_n).rev() {
                let solution = solve_ntru_intermediate(
                    params.log_n,
                    &decoded.f,
                    &decoded.g,
                    depth,
                    &reduced_f,
                    &reduced_g,
                )
                .expect("solve intermediate");
                reduced_f = solution.reduced_f;
                reduced_g = solution.reduced_g;
            }

            let depth1 = solve_ntru_binary_depth1(
                params.log_n,
                &decoded.f,
                &decoded.g,
                &reduced_f,
                &reduced_g,
            )
            .expect("solve binary depth1");
            let solution = solve_ntru_binary_depth0(
                params.log_n,
                &decoded.f,
                &decoded.g,
                &depth1.reduced_f,
                &depth1.reduced_g,
            )
            .expect("solve binary depth0");

            assert_eq!(solution.word_len, 1);
            assert_eq!(solution.reduced_f.len(), params.n);
            assert_eq!(solution.reduced_g.len(), params.n);
            for u in 0..params.n {
                assert_eq!(
                    zint_one_to_plain(&solution.reduced_f[u..u + 1]),
                    decoded.capital_f[u] as i32,
                    "capital F mismatch at coeff {u}"
                );
                assert_eq!(
                    zint_one_to_plain(&solution.reduced_g[u..u + 1]),
                    decoded.capital_g[u] as i32,
                    "capital G mismatch at coeff {u}"
                );
            }
        }
    }
}
