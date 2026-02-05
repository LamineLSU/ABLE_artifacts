rule Bypass_Sample {
    meta: {
        description: "Evasion bypass to skip detection checks",
        cape_options: "$pattern0=85 C0 0F 84 ?? ?? ?? ?? 8B 45 ??", 
                      "$pattern1=6A 5A 8B CE E8 ?? ?? ?? ?? ?? 85 C0",
                      "$pattern2=80 D0 C0 00 00 8B CD ?? ?? ?? ??" 
    }
}