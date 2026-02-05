rule BypassSample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 (C MP ), 74 20 (J E 00 41 B9 30 H) , ?? FO R TH E TA RG ET AD DR ES S }
        $pattern1 = { E8 ?? (C AL L DW OR D PT R [0 04 2F 13 CH ]) , 6A ?? , 5A ?? , 8B CE E8 ?? FO LL OW ED BY ?? FO R OF FS ET }
        $pattern2 = { 74 ?? (J E 00 41 B9 30 H) , 83 F8 01 (C MP ), ?? FO R TA RG ET AD DR ES S }

    condition:
        any of them
}