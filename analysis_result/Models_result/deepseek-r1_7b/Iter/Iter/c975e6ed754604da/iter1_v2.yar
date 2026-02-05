rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C4 55 85 C0 E8 FF ?? ?? ?? ?? } // Represents push ebp followed by mov ebp, esp and call
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Represents another unique sequence with displacement wildcards
        $pattern2 = { FF 45 FC E8 CE E8 ?? ?? ?? ?? ?? } // Another distinct pattern capturing a different context

    condition:
        any of them
}