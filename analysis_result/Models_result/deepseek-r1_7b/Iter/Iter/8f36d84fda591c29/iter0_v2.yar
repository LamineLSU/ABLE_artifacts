rule Bypass_Evasion {
    meta:
        description = "Evasion bypass using instruction skipping"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 83 9A ?? 0D 17 ?? ?? ?? ?? ?? FE FF }

    condition:
        any of them
}